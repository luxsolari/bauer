"""Unsigned run/decision receipts: consistency is not user authentication.

The host must ask in ordinary chat and STOP for a real later user response.
No local field or digest can prove that interaction happened.
"""
from datetime import datetime, timezone
from uuid import UUID, uuid4
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import hashlib
import json


def normalize_profile(value=None):
    spec = spec_from_file_location('bauer_run_profiles', Path(__file__).resolve().parent / 'profiles.py')
    if spec is None or spec.loader is None:
        raise ValueError('profiles unavailable')
    profiles = module_from_spec(spec)
    spec.loader.exec_module(profiles)
    return profiles.normalize(value)


SCHEMA = 'bauer-run-record-v2'
ORIGIN = 'control.py preflight; supplied provenance, not authenticated'
AUTHORITY = ('Record consistency only; user instruction/reference is supplied, not verified permission; '
             'cannot prevent fabricated input or verify chat delivery. No external calls authorized.')
CORE = ['dependency_coverage', 'remote_configuration', 'each relevant remote target']


def digest(value):
    """Public content digest, not a signature or an authenticity check."""
    return hashlib.sha256(json.dumps({k: v for k, v in value.items() if k != 'record_id'},
                                    sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def decision(value):
    if value in ({'state': 'not_requested'}, {'state': 'pending'}):
        return value
    fields = {'state', 'user_instruction', 'decision_ref', 'reason'}
    if (not isinstance(value, dict) or set(value) != fields or
            value['state'] != 'explicit_disable_captured' or
            any(not isinstance(v, str) or not v.strip() for v in value.values())):
        raise ValueError('disable requires supplied literal user instruction, reference and reason')
    return value


def profile_decision(value):
    if value == {'kind': 'default'}:
        return value
    if (not isinstance(value, dict) or set(value) != {'kind', 'user_instruction', 'decision_ref', 'reason'} or
            value['kind'] not in ('user_requested', 'agent_proposal') or
            any(not isinstance(v, str) or not v.strip() for v in value.values())):
        raise ValueError('profile choice requires literal decision and request/proposal label')
    return value


def validate(value, require_confirmed=False):
    fields = {'schema_version', 'run_id', 'record_id', 'created_at', 'origin', 'audit_profile',
              'excluded_sources', 'profile_decision', 'always_required', 'host_environment',
              'review_decision', 'chat_delivery', 'authority', 'scope_change', 'status', 'confirmation'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('invalid run record fields; unpublished v1 is unsupported')
    if value['schema_version'] != SCHEMA or value['origin'] != ORIGIN or value['authority'] != AUTHORITY:
        raise ValueError('unsupported run provenance')
    if any(not isinstance(value[k], str) or not value[k].strip() for k in ('run_id', 'created_at')):
        raise ValueError('run metadata requires text')
    identifier = UUID(value['run_id'])
    if identifier.version != 4 or str(identifier) != value['run_id']:
        raise ValueError('invalid run ID')
    timestamp = datetime.fromisoformat(value['created_at'].replace('Z', '+00:00'))
    if timestamp.tzinfo is None:
        raise ValueError('run timestamp requires timezone')
    profile = normalize_profile(value['audit_profile'])
    excluded = sorted(set(normalize_profile({'mode': 'full'})['selected_sources']) - set(profile['selected_sources']))
    if value['audit_profile'] != profile or value['always_required'] != CORE or value['excluded_sources'] != excluded:
        raise ValueError('run requires normalized profile, exclusions and core obligations')
    choice = profile_decision(value['profile_decision'])
    if choice == {'kind': 'default'} and profile != normalize_profile():
        raise ValueError('default cannot change Lean')
    env = value['host_environment']
    if (not isinstance(env, dict) or set(env) != {'key_present', 'key_availability'} or
            type(env['key_present']) is not bool or env['key_availability'] !=
            ('key_present' if env['key_present'] else 'missing_key')):
        raise ValueError('run requires boolean-only host presence')
    decision(value['review_decision'])
    if value['chat_delivery'] != 'pending_host_delivery':
        raise ValueError('helper cannot verify delivery')
    change = value['scope_change']
    if change is not None:
        fields = {'previous_run_id', 'previous_record_id', 'previous_audit_profile', 'reason', 'decision_ref', 'user_instruction'}
        if (not isinstance(change, dict) or set(change) != fields or
                any(not isinstance(change[k], str) or not change[k].strip() for k in fields - {'previous_audit_profile'})):
            raise ValueError('scope change requires previous run and supplied decision')
        previous_id = UUID(change['previous_run_id'])
        if previous_id.version != 4 or str(previous_id) != change['previous_run_id'] or str(previous_id) == value['run_id']:
            raise ValueError('scope change requires a different run ID')
        if (normalize_profile(change['previous_audit_profile']) != change['previous_audit_profile'] or
                len(change['previous_record_id']) != 64 or any(c not in '0123456789abcdef' for c in change['previous_record_id'])):
            raise ValueError('invalid previous record binding')
    status = value['status']
    confirmation = value['confirmation']
    if status == 'pending_confirmation':
        if confirmation is not None:
            raise ValueError('pending cannot carry confirmation')
    elif status in ('confirmed', 'declined'):
        fields = {'decision', 'user_response', 'response_ref', 'recorded_at', 'pending_record_id', 'pending_record'}
        if (not isinstance(confirmation, dict) or set(confirmation) != fields or
                confirmation['decision'] != ('confirm' if status == 'confirmed' else 'decline') or
                any(not isinstance(confirmation[k], str) or not confirmation[k].strip()
                    for k in fields - {'pending_record'})):
            raise ValueError('confirmation requires captured response and reference')
        pending = confirmation['pending_record']
        if not isinstance(pending, dict) or pending.get('status') != 'pending_confirmation':
            raise ValueError('confirmation must link pending record')
        validate(pending)
        if confirmation['pending_record_id'] != pending['record_id']:
            raise ValueError('wrong pending record reference')
        if any(value[k] != pending[k] for k in value if k not in ('status', 'confirmation', 'record_id')):
            raise ValueError('confirmation changed pinned decisions')
        recorded = datetime.fromisoformat(confirmation['recorded_at'].replace('Z', '+00:00'))
        if recorded.tzinfo is None or recorded < timestamp:
            raise ValueError('invalid confirmation timestamp')
    else:
        raise ValueError('invalid confirmation status')
    if value['record_id'] != digest(value):
        raise ValueError('record content mismatch; digest is unsigned')
    if require_confirmed and status != 'confirmed':
        raise ValueError('new audit requires confirmed decision record')
    return value


def create(profile, key_present, review_decision=None, scope_change=None, choice=None):
    value: dict = dict(schema_version=SCHEMA, run_id=str(uuid4()),
                 created_at=datetime.now(timezone.utc).isoformat(), origin=ORIGIN,
                 audit_profile=profile, always_required=list(CORE),
                 excluded_sources=sorted(set(normalize_profile({'mode': 'full'})['selected_sources']) - set(profile['selected_sources'])),
                 profile_decision=profile_decision(choice if choice is not None else {'kind': 'default'}),
                 host_environment=dict(key_present=key_present, key_availability='key_present' if key_present else 'missing_key'),
                 review_decision=decision(review_decision if review_decision is not None else dict(state='not_requested')),
                 chat_delivery='pending_host_delivery', scope_change=scope_change, authority=AUTHORITY,
                 status='pending_confirmation', confirmation=None)
    value['record_id'] = digest(value)
    return validate(value)


def confirm(pending, action, response, reference):
    validate(pending)
    if pending['status'] != 'pending_confirmation' or action not in ('confirm', 'decline'):
        raise ValueError('only a pending record can receive a decision')
    value = dict(pending, status='confirmed' if action == 'confirm' else 'declined',
                 confirmation=dict(decision=action, user_response=response, response_ref=reference,
                                   recorded_at=datetime.now(timezone.utc).isoformat(),
                                   pending_record_id=pending['record_id'], pending_record=pending))
    value['record_id'] = digest(value)
    return validate(value)
