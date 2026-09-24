"""Manifest-linked Android Network Security Configuration review signals.

These signals describe effective declarative policy for Android 7+ network stacks.
They do not prove that a connection is made or that a domain is first-party.
"""

from datetime import date, datetime, timezone
from pathlib import Path
import base64
import binascii
import re

from lxml import etree


ANDROID = '{http://schemas.android.com/apk/res/android}'
RESOURCE_NAME = re.compile(r'^@xml/([a-z][a-z0-9_]*)$')
MAX_CONFIG_BYTES = 1024 * 1024

CLEARTEXT_RULE = 'NETWORK_SECURITY_CLEARTEXT_DOMAIN_MEDIUM'
USER_CA_RULE = 'MSTG-NETWORK-4_user_trust_anchors'
EXPIRED_PIN_RULE = 'NETWORK_SECURITY_EXPIRED_PIN_SET_REVIEW'
RULE_IDS = (CLEARTEXT_RULE, USER_CA_RULE, EXPIRED_PIN_RULE)


def _parse_xml(path):
    parser = etree.XMLParser(resolve_entities=False, no_network=True,
                             load_dtd=False, recover=False, huge_tree=False)
    return etree.parse(str(path), parser).getroot()


def _signal(rule_id, path, element, detail):
    return {'rule_id': rule_id, 'path': str(path), 'element': element,
            'detail': detail}


def _domains(config):
    names = []
    for domain in config.findall('domain'):
        value = (domain.text or '').strip()
        if value:
            names.append(value[:253] + (' and subdomains' if domain.get('includeSubdomains') == 'true' else ''))
    return names


def _user_ca(config):
    anchors = config.find('trust-anchors')
    if anchors is None:
        return None
    return next((cert for cert in anchors.findall('certificates') if cert.get('src') == 'user'), None)


def _valid_pin(pin):
    if pin.get('digest') != 'SHA-256':
        return False
    try:
        decoded = base64.b64decode((pin.text or '').strip(), validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 32


def _resource_paths(name, roots):
    matches = []
    seen_qualifiers = set()
    for root in roots:
        if not root:
            continue
        base = Path(root)
        for resource_dir in (base / 'resources' / 'res', base / 'res'):
            if not resource_dir.is_dir() or resource_dir.is_symlink():
                continue
            try:
                folders = sorted(resource_dir.iterdir())
                for folder in folders:
                    if folder.name != 'xml' and not folder.name.startswith('xml-'):
                        continue
                    if folder.name in seen_qualifiers or folder.is_symlink() or not folder.is_dir():
                        continue
                    candidate = folder / f'{name}.xml'
                    if candidate.is_file() and not candidate.is_symlink() and candidate.resolve().is_relative_to(base.resolve()):
                        matches.append(candidate)
                        seen_qualifiers.add(folder.name)
                    if len(matches) > 32:
                        return matches[:32], True
            except OSError:
                continue
    return matches, False


def analyze_network_policy(manifest_path, recovered_roots, *, today=None):
    """Return policy signals and a bounded evaluation state for one APK."""
    result = {'status': 'unknown', 'path': None, 'reference': None,
              'variant_count': 0, 'evaluated_paths': [], 'signals': [], 'limitations': []}
    if not manifest_path:
        result['limitations'].append('No recovered manifest was available.')
        return result
    try:
        manifest = _parse_xml(manifest_path)
    except (OSError, etree.XMLSyntaxError, ValueError):
        result['limitations'].append('The recovered manifest could not be parsed.')
        return result
    application = manifest.find('application')
    reference = application.get(ANDROID + 'networkSecurityConfig') if application is not None else None
    result['reference'] = reference
    if not reference:
        result['status'] = 'not_configured'
        return result
    resource = RESOURCE_NAME.fullmatch(reference)
    if not resource:
        result['limitations'].append('The manifest networkSecurityConfig resource could not be resolved by name.')
        return result
    paths, truncated = _resource_paths(resource.group(1), recovered_roots)
    if not paths:
        result['limitations'].append('The referenced Network Security Configuration XML was not recovered.')
        return result
    result['path'] = str(paths[0])
    result['variant_count'] = len(paths)
    if truncated:
        result['limitations'].append('More than 32 matching XML resource variants were present; later variants were not evaluated.')
    if len(paths) > 1:
        result['limitations'].append('Multiple XML resource variants exist; device qualifier selection must be confirmed.')
    comparison_date = today or datetime.now(timezone.utc).date()
    unresolved = False
    for path in paths:
        variant = f'res/{path.parent.name}/{path.name}'
        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                result['limitations'].append(f'{variant} exceeds the 1 MiB parser limit.')
                continue
            config = _parse_xml(path)
        except (OSError, etree.XMLSyntaxError, ValueError):
            result['limitations'].append(f'{variant} could not be parsed.')
            continue
        if config.tag != 'network-security-config':
            result['limitations'].append(f'{variant} is not a network-security-config document.')
            continue
        result['evaluated_paths'].append(str(path))
        base = config.find('base-config')
        base_cleartext = base is not None and base.get('cleartextTrafficPermitted') == 'true'
        if base_cleartext:
            result['signals'].append(_signal(CLEARTEXT_RULE, path, base,
                                             f'{variant}: linked base-config explicitly permits cleartext for destinations without a more specific override.'))
        if base is not None:
            user_ca = _user_ca(base)
            if user_ca is not None:
                result['signals'].append(_signal(USER_CA_RULE, path, user_ca,
                                                 f'{variant}: linked release base-config explicitly trusts user-installed CAs.'))

        def visit(config_node, inherited_cleartext):
            nonlocal unresolved
            explicit = config_node.get('cleartextTrafficPermitted')
            effective_cleartext = inherited_cleartext if explicit is None else explicit == 'true'
            domains = _domains(config_node)
            scope = ', '.join(domains)
            if domains and effective_cleartext and not base_cleartext:
                result['signals'].append(_signal(CLEARTEXT_RULE, path, config_node,
                                                 f'{variant}: linked domain policy permits cleartext for {scope}.'))
            user_ca = _user_ca(config_node)
            if domains and user_ca is not None:
                result['signals'].append(_signal(USER_CA_RULE, path, user_ca,
                                                 f'{variant}: linked release domain policy trusts user-installed CAs for {scope}.'))
            pins = config_node.find('pin-set')
            if domains and pins is not None and any(_valid_pin(pin) for pin in pins.findall('pin')):
                expiration = pins.get('expiration')
                if expiration:
                    try:
                        if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', expiration):
                            raise ValueError('Expiration must use yyyy-MM-dd')
                        expiry = date.fromisoformat(expiration)
                    except ValueError:
                        result['limitations'].append(f'Invalid pin expiration in {variant} for {scope}; expiry was not evaluated.')
                        unresolved = True
                    else:
                        if expiry <= comparison_date:
                            result['signals'].append(_signal(EXPIRED_PIN_RULE, path, pins,
                                                             f'{variant}: pins for {scope} expired on {expiration}; first-party ownership and use need review.'))
            for child in config_node.findall('domain-config'):
                visit(child, effective_cleartext)

        for domain_config in config.findall('domain-config'):
            visit(domain_config, base_cleartext)
    result['status'] = ('evaluated' if len(result['evaluated_paths']) == len(paths) and not truncated and not unresolved else
                        'partial' if result['evaluated_paths'] else 'unknown')
    return result
