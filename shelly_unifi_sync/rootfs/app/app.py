#!/usr/bin/env python3
import os
import json
import logging
import subprocess
from flask import Flask, render_template, jsonify, request
from datetime import datetime

# Import sync_shelly funkcijos
from sync_shelly import load_ha_shelly_devices, UniFiREST, build_unifi_device_map, find_lan_network_id, sync_one

app = Flask(__name__)

# Logging setup
logging.basicConfig(
    level=logging.INFO if os.environ.get('DEBUG', 'false').lower() != 'true' else logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Global kintamieji
last_sync_time = None
sync_in_progress = False
sync_log = []


def add_log(level, message):
    """Pridėti žinutę į log"""
    global sync_log
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sync_log.append({
        'timestamp': timestamp,
        'level': level,
        'message': message
    })
    # Riboti log dydį
    if len(sync_log) > 500:
        sync_log = sync_log[-500:]
    
    # Taip pat loginti į console
    if level == 'error':
        logging.error(message)
    elif level == 'warning':
        logging.warning(message)
    else:
        logging.info(message)


@app.route('/')
def index():
    """Pagrindinis puslapis"""
    return render_template('index.html')


@app.route('/api/devices')
def get_devices():
    """Gauti Shelly įrenginių sąrašą"""
    try:
        # Gauti Shelly įrenginius iš HA
        ha_devices = load_ha_shelly_devices()
        
        # Bandyti prisijungti prie UniFi ir gauti info
        unifi_devices = {}
        try:
            unifi = UniFiREST(
                os.environ.get('UNIFI_HOST'),
                os.environ.get('UNIFI_USER'),
                os.environ.get('UNIFI_PASS'),
                os.environ.get('UNIFI_SITE', 'default'),
                port=int(os.environ.get('UNIFI_PORT', '443')),
                ssl_verify=os.environ.get('UNIFI_SSL_VERIFY', 'false').lower() == 'true'
            )
            
            if unifi.login():
                devices_map = build_unifi_device_map(unifi)
                for mac, device in devices_map.items():
                    unifi_devices[mac] = {
                        'name': device.get('name', ''),
                        'hostname': device.get('hostname', ''),
                        'ip': device.get('ip', ''),
                        'fixed_ip': device.get('fixed_ip', ''),
                        'use_fixedip': device.get('use_fixedip', False),
                        'online': device.get('_id') is not None and 'ip' in device
                    }
        except Exception as e:
            logging.error(f"Nepavyko gauti UniFi duomenų: {e}")
        
        # Sujungti HA ir UniFi duomenis
        devices = []
        for ha_device in ha_devices:
            mac = ha_device['mac'].lower()
            device_info = {
                'mac': mac,
                'ha_name': ha_device['name'],
                'unifi_info': unifi_devices.get(mac, {
                    'name': '',
                    'ip': '',
                    'fixed_ip': '',
                    'use_fixedip': False,
                    'online': False
                })
            }
            devices.append(device_info)
        
        return jsonify({
            'success': True,
            'devices': devices,
            'total': len(devices),
            'last_sync': last_sync_time
        })
        
    except Exception as e:
        logging.error(f"Klaida gaunant įrenginius: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/sync', methods=['POST'])
def sync_devices():
    """Paleisti sinchronizavimą"""
    global sync_in_progress, last_sync_time, sync_log
    
    if sync_in_progress:
        return jsonify({
            'success': False,
            'error': 'Sinchronizavimas jau vyksta'
        }), 409
    
    try:
        sync_in_progress = True
        sync_log = []  # Išvalyti seną log
        add_log('info', '=== Pradedamas sinchronizavimas ===')
        
        # Gauti Shelly įrenginius
        ha_devices = load_ha_shelly_devices()
        if not ha_devices:
            add_log('warning', 'Nerasta Shelly įrenginių')
            return jsonify({
                'success': False,
                'error': 'Nerasta Shelly įrenginių'
            }), 404
        
        add_log('info', f'Rasta {len(ha_devices)} Shelly įrenginių')
        
        # Prisijungti prie UniFi
        unifi = UniFiREST(
            os.environ.get('UNIFI_HOST'),
            os.environ.get('UNIFI_USER'),
            os.environ.get('UNIFI_PASS'),
            os.environ.get('UNIFI_SITE', 'default'),
            port=int(os.environ.get('UNIFI_PORT', '443')),
            ssl_verify=os.environ.get('UNIFI_SSL_VERIFY', 'false').lower() == 'true'
        )
        
        if not unifi.login():
            add_log('error', 'Nepavyko prisijungti prie UniFi controller')
            return jsonify({
                'success': False,
                'error': 'Nepavyko prisijungti prie UniFi controller'
            }), 401
        
        add_log('info', 'Sėkmingai prisijungta prie UniFi')
        
        # Gauti UniFi duomenis
        devices_map = build_unifi_device_map(unifi)
        lan_id = find_lan_network_id(unifi)
        
        if not lan_id:
            add_log('warning', 'LAN tinklo ID nerastas')
        
        # Sinchronizuoti kiekvieną įrenginį
        success_count = 0
        error_count = 0
        
        for device in ha_devices:
            mac = device['mac'].lower()
            name = device['name']
            add_log('info', f'Apdorojamas: {name} ({mac})')
            
            try:
                unifi_device = devices_map.get(mac)
                if not unifi_device:
                    add_log('warning', f'Įrenginys {mac} nerastas UniFi')
                
                sync_one(unifi, lan_id, device, unifi_device)
                success_count += 1
                add_log('info', f'✓ {name} sinchronizuotas')
                
            except Exception as e:
                error_count += 1
                add_log('error', f'✗ {name}: {str(e)}')
        
        last_sync_time = datetime.now().isoformat()
        add_log('info', f'=== Sinchronizavimas baigtas: {success_count} sėkmingai, {error_count} klaidų ===')
        
        return jsonify({
            'success': True,
            'synced': success_count,
            'errors': error_count,
            'total': len(ha_devices),
            'last_sync': last_sync_time
        })
        
    except Exception as e:
        add_log('error', f'Kritinė klaida: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        
    finally:
        sync_in_progress = False


@app.route('/api/sync/<mac>', methods=['POST'])
def sync_single_device(mac):
    """Sinchronizuoti vieną įrenginį"""
    global sync_log
    
    try:
        mac = mac.lower()
        add_log('info', f'Pradedamas vieno įrenginio sinchronizavimas: {mac}')
        
        # Rasti įrenginį
        ha_devices = load_ha_shelly_devices()
        device = None
        for d in ha_devices:
            if d['mac'].lower() == mac:
                device = d
                break
        
        if not device:
            return jsonify({
                'success': False,
                'error': 'Įrenginys nerastas'
            }), 404
        
        # Prisijungti prie UniFi
        unifi = UniFiREST(
            os.environ.get('UNIFI_HOST'),
            os.environ.get('UNIFI_USER'),
            os.environ.get('UNIFI_PASS'),
            os.environ.get('UNIFI_SITE', 'default'),
            port=int(os.environ.get('UNIFI_PORT', '443')),
            ssl_verify=os.environ.get('UNIFI_SSL_VERIFY', 'false').lower() == 'true'
        )
        
        if not unifi.login():
            return jsonify({
                'success': False,
                'error': 'Nepavyko prisijungti prie UniFi'
            }), 401
        
        # Gauti UniFi duomenis
        devices_map = build_unifi_device_map(unifi)
        lan_id = find_lan_network_id(unifi)
        
        # Sinchronizuoti
        unifi_device = devices_map.get(mac)
        sync_one(unifi, lan_id, device, unifi_device)
        
        add_log('info', f'✓ {device["name"]} sinchronizuotas')
        
        return jsonify({
            'success': True,
            'device': device["name"]
        })
        
    except Exception as e:
        add_log('error', f'Klaida sinchronizuojant {mac}: {str(e)}')
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/logs')
def get_logs():
    """Gauti sinchronizavimo log"""
    return jsonify({
        'logs': sync_log
    })


@app.route('/api/status')
def get_status():
    """Gauti addon statusą"""
    return jsonify({
        'sync_in_progress': sync_in_progress,
        'last_sync': last_sync_time,
        'unifi_host': os.environ.get('UNIFI_HOST'),
        'unifi_site': os.environ.get('UNIFI_SITE'),
        'name_prefix': os.environ.get('NAME_PREFIX')
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8099, debug=True)