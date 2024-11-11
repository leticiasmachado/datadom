import json
from jsonschema import validate, ValidationError

def load_schema(schema_path):    
    with open(schema_path, 'r') as schema_file:
        return json.load(schema_file)

def load_config(config_path):
    with open(config_path, 'r') as config_file:
        return json.load(config_file)

def validate_json(config_data, schema):
    try:
        validate(instance=config_data, schema=schema)
        return True, "JSON is valid."
    except ValidationError as e:
        return False, f"JSON is invalid: {e.message}"

