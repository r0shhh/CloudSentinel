import yaml
import os


def load_checks_config(config_path=None):
    """
    Load checks configuration from YAML file.
    Returns a dictionary of checks with their settings.
    """
    if config_path is None:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base_dir, 'checks.yaml')


    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)

    return config['checks']

def get_enabled_checks(service=None):
    """
    Return only enabled checks, optionally filtered by service
    """
    checks = load_checks_config()

    enabled = {
        name: check
        for name, check in checks.items()
        if check.get('enabled', True)
    }

    if service and service != 'all':
        enabled = {
            name: check
            for name, check in enabled.items()
            if check.get('service') == service 
        }

    return enabled