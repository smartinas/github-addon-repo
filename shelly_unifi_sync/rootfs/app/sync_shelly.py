#!/usr/bin/env python3
"""
Shelly UniFi Sync - pagrindinės funkcijos su hostname palaikymu
Šis failas importuojamas Flask app ir gali būti naudojamas atskirai
"""
import os
import json
import logging
import time
import base64
from typing import List, Dict, Optional, Set, Tuple

import requests
from requests.exceptions import RequestException

# Logging handler pridėjimui prie Flask app
sync_logger = logging.getLogger('sync_shelly')


def load_ha_shelly_devices() -> List[Dict[str, str]]:
    """Nuskaityti Shelly įrenginius iš Home Assistant"""
    ha_config_path = os.environ.get("HA_CONFIG_PATH", "/config")
    device_registry_path = os.path.join(ha_config_path, ".storage", "core.device_registry")

    sync_logger.info(f"Nuskaitomas įrenginių registras iš: {device_registry_path}")

    try:
        with open(device_registry_path, encoding='utf-8') as f:
            registry = json.load(f)
    except Exception as e:
        sync_logger.error(f"Nepavyko atidaryti registro: {e}")
        return []

    devices = []
    for device in registry.get("data", {}).get("devices", []):
        if device.get("manufacturer") != "Shelly":
            continue

        mac_address = None
        device_name = device.get("name_by_user") or device.get("name") or ""

        # Ieškoti MAC connections
        for conn in device.get("connections", []):
            if isinstance(conn, list) and len(conn) >= 2 and conn[0] == "mac":
                mac_address = conn[1].lower()
                break

        # Jei nerastas, bandyti iš identifiers
        if not mac_address:
            for identifier in device.get("identifiers", []):
                if isinstance(identifier, list) and len(identifier) >= 2 and identifier[0] == "shelly" and '-' in \
                        identifier[1]:
                    potential = identifier[1].split('-')[-1]
                    if len(potential) == 12:
                        mac_address = ":".join(potential[i:i + 2] for i in range(0, 12, 2)).lower()
                        break

        if device_name and mac_address:
            devices.append({"name": device_name.strip(), "mac": mac_address})
            sync_logger.info(f"Rastas HA Shelly įrenginys: '{device_name}' ({mac_address})")
        else:
            sync_logger.warning(f"PRALEIDŽIAMA: Shelly įrenginys '{device_name}' be galimo MAC arba vardo.")

    return devices


class UniFiREST:
    """UniFi REST API klientas"""

    def __init__(self, host, user, password, site, port=443, ssl_verify=False):
        self.base = f"https://{host}:{port}"
        self.site = site
        self.user = user
        self.password = password
        self.session = requests.Session()
        self.session.verify = ssl_verify
        self.is_unifi_os = False
        self.csrf = None

    def login(self) -> bool:
        """Prisijungti prie UniFi controller"""
        try:
            r = self.session.get(f"{self.base}/", timeout=10)
            if r.status_code == 200:
                self.is_unifi_os = True
                login_url = f"{self.base}/api/auth/login"
            else:
                login_url = f"{self.base}/api/login"
        except RequestException as e:
            sync_logger.error(f"KLAIDA jungiantis prie controllerio: {e}")
            return False

        payload = {"username": self.user, "password": self.password}
        headers = {'Content-Type': 'application/json'}
        r = self.session.post(login_url, json=payload, headers=headers, timeout=10)

        if r.status_code not in (200, 201):
            sync_logger.error(f"Login failed, HTTP {r.status_code}: {r.text.strip()}")
            return False

        self._extract_csrf_from_cookie()
        sync_logger.info("Sėkmingai prisijungta prie UniFi.")
        return True

    def _extract_csrf_from_cookie(self):
        """Išgauti CSRF token iš cookie"""
        token = None
        for name, value in self.session.cookies.get_dict().items():
            if name.upper().startswith("TOKEN"):
                token = value
                break
        if not token:
            return
        try:
            parts = token.split('.')
            if len(parts) >= 2:
                payload_b64 = parts[1]
                padding = '=' * (-len(payload_b64) % 4)
                decoded = base64.urlsafe_b64decode(payload_b64 + padding)
                obj = json.loads(decoded)
                self.csrf = obj.get('csrfToken')
                if self.csrf:
                    self.session.headers.update({'x-csrf-token': self.csrf})
        except Exception:
            sync_logger.debug("Nepavyko išgauti CSRF token iš TOKEN cookie.", exc_info=True)

    def _full_path(self, path: str) -> str:
        """Sudaryti pilną API kelią"""
        if self.is_unifi_os and path.startswith('/api/'):
            return f"{self.base}/proxy/network{path}"
        return f"{self.base}{path}"

    def request(self, method: str, path: str, payload=None, params=None, boolean=False):
        """Atlikti API užklausą"""
        url = self._full_path(path)
        try:
            if method.upper() == 'GET':
                r = self.session.get(url, params=params, timeout=15)
            elif method.upper() == 'POST':
                r = self.session.post(url, json=payload, timeout=15)
            elif method.upper() == 'PUT':
                r = self.session.put(url, json=payload, timeout=15)
            elif method.upper() == 'DELETE':
                r = self.session.delete(url, json=payload, timeout=15)
            else:
                raise ValueError(f"Nepalaikomas metodas {method}")
        except RequestException as e:
            sync_logger.error(f"HTTP klaida {method} {url}: {e}")
            return False if boolean else None

        if r.status_code == 401:
            sync_logger.warning("401: bandymas prisijungti iš naujo")
            if self.login():
                return self.request(method, path, payload, params, boolean=boolean)
            else:
                return False if boolean else None

        if r.status_code >= 400:
            sync_logger.error(f"API klaida {r.status_code} {method} {url}: {r.text.strip()}")
            return False if boolean else None

        try:
            data = r.json()
        except ValueError:
            sync_logger.error(f"Nepavyko dekoduoti JSON iš atsakymo: {r.text.strip()}")
            return False if boolean else None

        # Handle different response formats
        if isinstance(data, dict):
            # V2 API error
            if 'errorCode' in data and data['errorCode']:
                sync_logger.error(f"V2 API klaida: {data.get('message', '')}")
                return False if boolean else None

            # Standard meta response
            if 'meta' in data:
                if data['meta'].get('rc') == 'ok':
                    if boolean:
                        return True
                    if 'data' in data:
                        return data['data']
                    return data
                else:
                    msg = data['meta'].get('msg', 'unknown error')
                    sync_logger.error(f"Controller grąžino klaidą: {msg}")
                    return False if boolean else None

        # Return data as-is if no special format
        return data if not boolean else True

    def get(self, path, **kwargs):
        return self.request('GET', path, **kwargs)

    def post(self, path, **kwargs):
        return self.request('POST', path, **kwargs)

    def put(self, path, **kwargs):
        return self.request('PUT', path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request('DELETE', path, **kwargs)


def find_lan_network_id(u: UniFiREST) -> Optional[str]:
    """Ieškoti LAN tinklo ID"""
    candidates = []

    # Bandyti abu endpoint'us
    nets = u.get(f"/api/s/{u.site}/rest/networkconf")
    if nets is not None:
        candidates.append(nets)

    legacy = u.get(f"/api/s/{u.site}/list/networkconf")
    if legacy is not None:
        candidates.append(legacy)

    if not candidates:
        sync_logger.error("KLAIDA gaunant tinklų sąrašą iš nė vieno endpoint'o.")
        return None

    all_nets = []
    for batch in candidates:
        if isinstance(batch, list):
            all_nets.extend(batch)
        elif isinstance(batch, dict) and 'data' in batch:
            data = batch.get('data')
            if isinstance(data, list):
                all_nets.extend(data)
        elif isinstance(batch, dict):
            all_nets.append(batch)

    # Ieškoti corporate/LAN tinklo
    for net in all_nets:
        purpose = (net.get("purpose") or "").lower()
        name = (net.get("name") or "").lower()
        sync_logger.info(f"Tinklo patikrinimas: name='{name}', purpose='{purpose}', _id='{net.get('_id')}'")
        if purpose == "corporate":
            sync_logger.info(f"Rastas corporate tinklas su ID: {net.get('_id')}")
            return net.get("_id")

    # Jei nerastas corporate, grąžinti pirmą
    if all_nets:
        sync_logger.warning("Nerastas corporate tinklas, naudojamas pirmas rastas")
        return all_nets[0].get("_id")

    sync_logger.error("KLAIDA: Nerastas joks tinklas.")
    return None


def build_unifi_device_map(u: UniFiREST) -> Dict[str, dict]:
    """Sukurti MAC -> device žemėlapį iš UniFi duomenų (legacy funkcija compatibility)"""
    devices_by_mac, _ = build_unifi_device_maps(u)
    return devices_by_mac


def build_unifi_device_maps(u: UniFiREST) -> Tuple[Dict[str, dict], Dict[str, List[dict]]]:
    """
    Sukurti:
    - MAC -> device žemėlapį
    - Hostname -> devices list žemėlapį
    """
    devices_by_mac = {}
    devices_by_hostname = {}

    # Gauti online klientus
    clients = u.get(f"/api/s/{u.site}/stat/sta")
    if isinstance(clients, list):
        for client in clients:
            mac = (client.get("mac") or "").lower()
            hostname = (client.get("hostname") or "").lower()

            if mac:
                devices_by_mac[mac] = client

            if hostname:
                if hostname not in devices_by_hostname:
                    devices_by_hostname[hostname] = []
                devices_by_hostname[hostname].append(client)

    # Gauti visus žinomus vartotojus
    users = u.get(f"/api/s/{u.site}/list/user")
    if isinstance(users, list):
        for user in users:
            mac = (user.get("mac") or "").lower()
            hostname = (user.get("hostname") or "").lower()

            if mac and mac not in devices_by_mac:  # Nepakeisti jei jau yra online versija
                devices_by_mac[mac] = user

            if hostname:
                if hostname not in devices_by_hostname:
                    devices_by_hostname[hostname] = []
                # Tikrinti ar jau nėra to paties MAC
                existing_macs = [d.get("mac", "").lower() for d in devices_by_hostname[hostname]]
                if mac not in existing_macs:
                    devices_by_hostname[hostname].append(user)

    sync_logger.info(f"Iš viso UniFi žinomų įrenginių pagal MAC: {len(devices_by_mac)}")
    sync_logger.info(f"Iš viso UniFi žinomų hostname: {len(devices_by_hostname)}")

    # Debug: parodyti hostname su keliais MAC
    for hostname, devs in devices_by_hostname.items():
        if len(devs) > 1 and hostname.startswith("shelly"):
            macs = [d.get("mac", "").lower() for d in devs]
            sync_logger.info(f"Hostname '{hostname}' turi {len(devs)} MAC adresus: {macs}")

    return devices_by_mac, devices_by_hostname


def create_new_user(u: UniFiREST, mac: str, name: str) -> Optional[str]:
    """Sukurti naują vartotoją UniFi sistemoje"""
    # Gauti default user group
    usergroups = u.get(f"/api/s/{u.site}/list/usergroup")
    default_group_id = None

    if isinstance(usergroups, list) and len(usergroups) > 0:
        # Ieškoti "Default" grupės arba imti pirmą
        for group in usergroups:
            if (group.get("name") or "").lower() == "default":
                default_group_id = group.get("_id")
                break
        if not default_group_id:
            default_group_id = usergroups[0].get("_id")

    if not default_group_id:
        sync_logger.error("Nerasta vartotojų grupė")
        return None

    # Sukurti vartotoją
    name_prefix = os.environ.get('NAME_PREFIX', 'SHELLY ')
    payload = {
        "mac": mac.lower(),
        "usergroup_id": default_group_id,
        "name": f"{name_prefix}{name}".strip()
    }

    # Bandyti per group/user endpoint
    result = u.post(f"/api/s/{u.site}/group/user", payload={"objects": [{"data": payload}]})
    if result and isinstance(result, list) and len(result) > 0:
        user_id = result[0].get("_id")
        sync_logger.info(f"Sukurtas naujas vartotojas su ID: {user_id}")
        return user_id

    sync_logger.error("Nepavyko sukurti vartotojo")
    return None


def update_device_name(u: UniFiREST, device_id: str, name: str) -> bool:
    """Atnaujinti įrenginio vardą"""
    name_prefix = os.environ.get('NAME_PREFIX', 'SHELLY ')
    desired_name = f"{name_prefix}{name}".strip()
    payload = {'name': desired_name}

    # Bandyti REST endpoint
    result = u.put(f"/api/s/{u.site}/rest/user/{device_id}", payload=payload)
    if result:
        sync_logger.info(f"Vardas atnaujintas per REST: '{desired_name}'")
        return True

    # Bandyti legacy endpoint
    result = u.put(f"/api/s/{u.site}/upd/user/{device_id}", payload=payload)
    if result:
        sync_logger.info(f"Vardas atnaujintas per legacy: '{desired_name}'")
        return True

    sync_logger.warning("Nepavyko atnaujinti vardo")
    return False


def update_fixed_ip(u: UniFiREST, device_id: str, mac: str, lan_network_id: str,
                    current_ip: Optional[str] = None) -> bool:
    """Įjungti fixed IP įrenginiui"""

    payload = {
        '_id': device_id,
        'use_fixedip': True
    }

    if lan_network_id:
        payload['network_id'] = lan_network_id

    # Jei turime IP, galime iškart bandyti jį nustatyti
    if current_ip:
        payload['fixed_ip'] = current_ip

    sync_logger.info(f"Bandoma įjungti fixed IP su payload: {payload}")

    # Bandyti REST endpoint
    result = u.put(f"/api/s/{u.site}/rest/user/{device_id}", payload=payload)

    if not result:
        # Bandyti legacy endpoint
        result = u.put(f"/api/s/{u.site}/upd/user/{device_id}", payload=payload)

    if result:
        sync_logger.info(f"Fixed IP nustatymai atnaujinti įrenginiui {mac}")
        return True
    else:
        sync_logger.error(f"Nepavyko atnaujinti fixed IP nustatymų įrenginiui {mac}")
        return False


def sync_one_device(u: UniFiREST, lan_network_id: Optional[str], unifi_device: dict, target_name: str) -> str:
    """
    Sinchronizuoti vieną UniFi įrenginį
    Grąžina hostname jei atnaujintas sėkmingai
    """

    mac = unifi_device.get('mac', '').lower()
    dev_id = unifi_device.get('_id')
    hostname = (unifi_device.get('hostname') or '').lower()

    if not dev_id:
        sync_logger.warning(f"UniFi įrenginys su MAC {mac} neturi ID, praleidžiama.")
        return ""

    # 1. Atnaujinti vardą
    name_prefix = os.environ.get('NAME_PREFIX', 'SHELLY ')
    current_name = unifi_device.get('name') or unifi_device.get('hostname') or ""
    desired_name = f"{name_prefix}{target_name}".strip()

    if current_name != desired_name:
        sync_logger.info(f"VARDAS: keičiamas iš '{current_name}' į '{desired_name}'")
        update_device_name(u, dev_id, target_name)
    else:
        sync_logger.info("VARDAS: jau sinchronizuotas.")

    # 2. Nustatyti Fixed IP
    if lan_network_id:
        use_fixedip = unifi_device.get('use_fixedip', False)
        fixed_ip = unifi_device.get('fixed_ip')
        current_ip = unifi_device.get('ip') or fixed_ip

        if not use_fixedip or not fixed_ip:
            sync_logger.info(f"FIXED IP: Įjungiamas fixed IP įrenginiui {mac}")
            success = update_fixed_ip(u, dev_id, mac, lan_network_id, current_ip)
            if success:
                sync_logger.info(f"FIXED IP: Sėkmingai nustatytas" + (f" su IP {current_ip}" if current_ip else ""))
            else:
                sync_logger.error(f"FIXED IP: Nepavyko nustatyti")
        else:
            sync_logger.info(f"FIXED IP: Jau įjungtas ({fixed_ip})")
    else:
        sync_logger.warning("FIXED IP: LAN tinklo ID nerastas, negalima priskirti.")

    return hostname


def sync_one(u: UniFiREST, lan_network_id: Optional[str], ha_device: Dict[str, str], unifi_device: Optional[dict]):
    """
    Legacy funkcija compatibility - naudoja naują logiką su hostname palaikymu
    """
    mac = ha_device['mac'].lower()
    name = ha_device['name']

    # Jei įrenginys nerastas UniFi, sukurti naują
    if not unifi_device:
        sync_logger.info(f"Įrenginys {mac} nerastas UniFi, bandoma sukurti")
        user_id = create_new_user(u, mac, name)
        if not user_id:
            sync_logger.error(f"Nepavyko sukurti vartotojo įrenginiui {mac}")
            return
        # Atnaujinti unifi_device su naujai sukurtu
        devices_map = build_unifi_device_map(u)
        unifi_device = devices_map.get(mac)
        if not unifi_device:
            sync_logger.error(f"Nepavyko rasti naujai sukurto įrenginio {mac}")
            return

    # Sinchronizuoti įrenginį ir gauti hostname
    hostname = sync_one_device(u, lan_network_id, unifi_device, name)

    # Jei turime hostname, ieškoti susijusių įrenginių
    if hostname and hostname.startswith("shelly"):
        sync_logger.info(f"Tikrinami kiti įrenginiai su hostname '{hostname}'")

        # Gauti visus įrenginius
        devices_by_mac, devices_by_hostname = build_unifi_device_maps(u)

        if hostname in devices_by_hostname:
            devices_with_hostname = devices_by_hostname[hostname]

            for related_device in devices_with_hostname:
                related_mac = related_device.get('mac', '').lower()

                # Praleisti jei tai tas pats įrenginys
                if related_mac == mac:
                    continue

                # Tikrinti ar šis įrenginys neturi vardo arba turi tik hostname
                current_name = related_device.get('name', '')
                if not current_name or current_name == related_device.get('hostname', ''):
                    sync_logger.info(
                        f"Rastas susijęs įrenginys {related_mac} su hostname '{hostname}', pritaikomas vardas '{name}'")
                    sync_one_device(u, lan_network_id, related_device, name)
                else:
                    sync_logger.info(f"MAC {related_mac} jau turi vardą '{current_name}', praleidžiama")


def sync_all_with_hostname_support(u: UniFiREST, lan_network_id: Optional[str], ha_devices: List[Dict[str, str]]):
    """
    Pilna sinchronizacija su hostname palaikymu
    """
    # Gauti visus UniFi įrenginius
    devices_by_mac, devices_by_hostname = build_unifi_device_maps(u)

    # Saugoti atnaujintų hostname -> vardas žemėlapį
    updated_hostnames = {}  # hostname -> target_name
    processed_macs = set()

    # PIRMAS ETAPAS: Atnaujinti visus įrenginius iš Home Assistant
    sync_logger.info("=== ETAPAS 1: Sinchronizuojami įrenginiai iš Home Assistant ===")

    for dev in ha_devices:
        mac = dev['mac'].lower()
        name = dev['name']

        if mac in processed_macs:
            continue

        sync_logger.info(f"--- Apdorojamas Shelly įrenginys: '{name}' ({mac}) ---")

        unifi_device = devices_by_mac.get(mac)
        if unifi_device:
            hostname = sync_one_device(u, lan_network_id, unifi_device, name)
            processed_macs.add(mac)

            # Išsaugoti hostname -> vardas susiejimą
            if hostname and hostname.startswith("shelly"):
                updated_hostnames[hostname] = name
                sync_logger.info(f"Išsaugotas hostname mapping: {hostname} -> {name}")
        else:
            sync_logger.warning(f"Įrenginys su MAC {mac} nerastas UniFi, bandoma sukurti")
            user_id = create_new_user(u, mac, name)
            if user_id:
                # Atnaujinti žemėlapius ir bandyti dar kartą
                devices_by_mac, devices_by_hostname = build_unifi_device_maps(u)
                unifi_device = devices_by_mac.get(mac)
                if unifi_device:
                    hostname = sync_one_device(u, lan_network_id, unifi_device, name)
                    processed_macs.add(mac)
                    if hostname and hostname.startswith("shelly"):
                        updated_hostnames[hostname] = name

    # ANTRAS ETAPAS: Rasti ir atnaujinti įrenginius su tais pačiais hostname
    sync_logger.info("=== ETAPAS 2: Sinchronizuojami susijusio hostname įrenginiai ===")

    for hostname, target_name in updated_hostnames.items():
        if hostname not in devices_by_hostname:
            continue

        sync_logger.info(f"--- Tikrinamas hostname '{hostname}' (vardas: '{target_name}') ---")

        devices_with_hostname = devices_by_hostname[hostname]
        for unifi_device in devices_with_hostname:
            mac = unifi_device.get('mac', '').lower()

            if mac in processed_macs:
                sync_logger.info(f"MAC {mac} jau apdorotas, praleidžiama")
                continue

            # Tikrinti ar šis įrenginys neturi vardo arba turi tik hostname
            current_name = unifi_device.get('name', '')
            if not current_name or current_name == unifi_device.get('hostname', ''):
                sync_logger.info(
                    f"Rastas susijęs įrenginys {mac} su hostname '{hostname}', pritaikomas vardas '{target_name}'")
                sync_one_device(u, lan_network_id, unifi_device, target_name)
                processed_macs.add(mac)
            else:
                sync_logger.info(f"MAC {mac} jau turi vardą '{current_name}', praleidžiama")

    # TREČIAS ETAPAS: Papildomas patikrinimas - rasti įrenginius su panašiais hostname
    sync_logger.info("=== ETAPAS 3: Papildomas patikrinimas pagal MAC prefiksą ===")

    for hostname, devices in devices_by_hostname.items():
        if not hostname.startswith("shelly"):
            continue

        # Jau apdoroti hostname
        if hostname in updated_hostnames:
            continue

        # Bandyti rasti susijusį įrenginį pagal MAC prefiksą
        if '-' in hostname:
            hostname_mac_part = hostname.split('-')[-1]
            if len(hostname_mac_part) == 12:
                # Konvertuoti į MAC formatą
                hostname_mac = ":".join(hostname_mac_part[i:i + 2] for i in range(0, 12, 2)).lower()
                hostname_mac_prefix = ":".join(hostname_mac.split(":")[:-1])  # Be paskutinio okteto

                # Ieškoti atitinkamo HA įrenginio
                for ha_device in ha_devices:
                    ha_mac = ha_device['mac'].lower()
                    ha_mac_prefix = ":".join(ha_mac.split(":")[:-1])

                    if ha_mac_prefix == hostname_mac_prefix:
                        sync_logger.info(f"Rastas susijęs hostname '{hostname}' pagal MAC prefiksą")

                        for unifi_device in devices:
                            mac = unifi_device.get('mac', '').lower()
                            if mac not in processed_macs:
                                current_name = unifi_device.get('name', '')
                                if not current_name or current_name == unifi_device.get('hostname', ''):
                                    sync_logger.info(f"Sinchronizuojamas susijęs įrenginys {mac}")
                                    sync_one_device(u, lan_network_id, unifi_device, ha_device['name'])
                                    processed_macs.add(mac)
                        break

    sync_logger.info(f"=== Santrauka ===")
    sync_logger.info(f"Apdorota įrenginių: {len(processed_macs)}")
    sync_logger.info(f"Atnaujinta hostname grupių: {len(updated_hostnames)}")


# Main funkcija jei paleidžiama tiesiogiai
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    print("Naudokite Flask app arba importuokite funkcijas")