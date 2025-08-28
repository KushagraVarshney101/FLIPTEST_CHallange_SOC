import pandas as pd
import json
import re
import sys
from typing import Dict, List, Tuple, Any

class PIIDetector:
    def __init__(self):
        self.phone_pattern = re.compile(r'\b\d{10}\b')
        self.aadhar_pattern = re.compile(r'\b\d{12}\b')
        self.passport_pattern = re.compile(r'\b[A-Z]\d{7}\b')
        self.upi_pattern = re.compile(r'\b(?:\w+@\w+|\d{10}@\w+)\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.pincode_pattern = re.compile(r'\b\d{6}\b')
        self.full_name_pattern = re.compile(r'^[A-Z][a-z]+ [A-Z][a-z]+(?:\s[A-Z][a-z]+)*$')
        self.first_name_pattern = re.compile(r'^[A-Z][a-z]+$')
        self.last_name_pattern = re.compile(r'^[A-Z][a-z]+$')
        self.address_pattern = re.compile(r'.+,\s*.+,\s*\d{6}')
        self.standalone_pii_fields = {'phone', 'aadhar', 'passport', 'upi_id'}
        self.combinatorial_pii_fields = {'name', 'email', 'address', 'ip_address', 'device_id'}
        
    def is_phone_number(self, value: str) -> bool:
        try:
            if 'e+' in str(value):
                value = f"{float(value):.0f}"
            return bool(self.phone_pattern.fullmatch(str(value)))
        except:
            return False
    
    def is_aadhar_number(self, value: str) -> bool:
        try:
            if 'e+' in str(value):
                value = f"{float(value):.0f}"
            return bool(self.aadhar_pattern.fullmatch(str(value)))
        except:
            return False
    
    def is_passport_number(self, value: str) -> bool:
        return bool(self.passport_pattern.fullmatch(str(value)))
    
    def is_upi_id(self, value: str) -> bool:
        return bool(self.upi_pattern.fullmatch(str(value)))
    
    def is_email(self, value: str) -> bool:
        return bool(self.email_pattern.fullmatch(str(value)))
    
    def is_full_name(self, value: str) -> bool:
        return bool(self.full_name_pattern.fullmatch(str(value)))
    
    def is_address(self, value: str) -> bool:
        return bool(self.address_pattern.search(str(value)))
    
    def is_ip_address(self, value: str) -> bool:
        return bool(self.ip_pattern.fullmatch(str(value)))
    
    def has_combinatorial_pii(self, data: Dict) -> Tuple[bool, List[str]]:
        pii_count = 0
        pii_elements = []
        
        for key, value in data.items():
            if key == 'name' and self.is_full_name(value):
                pii_count += 1
                pii_elements.append('name')
            elif key == 'email' and self.is_email(value):
                pii_count += 1
                pii_elements.append('email')
            elif key == 'address' and self.is_address(value):
                pii_count += 1
                pii_elements.append('address')
            elif key in ['ip_address', 'device_id'] and value:
                pii_count += 1
                pii_elements.append(key)
            elif key in ['first_name', 'last_name'] and value:
                if 'first_name' in data and 'last_name' in data:
                    if 'name_combination' not in pii_elements:
                        pii_count += 1
                        pii_elements.append('name_combination')
        
        return pii_count >= 2, pii_elements
    
    def detect_pii(self, data: Dict) -> Tuple[bool, List[str]]:
        """Detect PII in a data record"""
        pii_found = False
        pii_fields = []
        for key, value in data.items():
            if key == 'phone' and self.is_phone_number(value):
                pii_found = True
                pii_fields.append(key)
            elif key == 'aadhar' and self.is_aadhar_number(value):
                pii_found = True
                pii_fields.append(key)
            elif key == 'passport' and self.is_passport_number(value):
                pii_found = True
                pii_fields.append(key)
            elif key == 'upi_id' and self.is_upi_id(value):
                pii_found = True
                pii_fields.append(key)
        
        has_combo_pii, combo_elements = self.has_combinatorial_pii(data)
        if has_combo_pii:
            pii_found = True
            pii_fields.extend(combo_elements)
        
        return pii_found, pii_fields
    
    def redact_value(self, key: str, value: str) -> str:
        """Redact PII values based on type"""
        value_str = str(value)
        
        if key == 'phone' and self.is_phone_number(value):
            if 'e+' in value_str:
                value_str = f"{float(value):.0f}"
            return value_str[:2] + "X" * 6 + value_str[-2:]
        elif key == 'aadhar' and self.is_aadhar_number(value):
            if 'e+' in value_str:
                value_str = f"{float(value):.0f}"
            return value_str[:3] + "X" * 6 + value_str[-3:]
        elif key == 'passport' and self.is_passport_number(value):
            return value_str[0] + "X" * (len(value_str) - 2) + value_str[-1]
        elif key == 'upi_id' and self.is_upi_id(value):
            if '@' in value_str:
                parts = value_str.split('@')
                return parts[0][:2] + "X" * (len(parts[0]) - 2) + "@" + parts[1]
            return "REDACTED_UPI"
        elif key == 'email' and self.is_email(value):
            parts = value_str.split('@')
            username = parts[0][:2] + "X" * (len(parts[0]) - 2) if len(parts[0]) > 2 else "XX"
            return username + "@" + parts[1]
        elif key == 'name' and self.is_full_name(value):
            names = value_str.split()
            redacted_names = [name[0] + "X" * (len(name) - 1) for name in names]
            return " ".join(redacted_names)
        elif key in ['first_name', 'last_name']:
            return value_str[0] + "X" * (len(value_str) - 1) if len(value_str) > 1 else "X"
        elif key == 'address' and self.is_address(value):
            parts = value_str.split(',')
            if len(parts) >= 3:
                parts[0] = "XXX " + parts[0].split()[-1] if ' ' in parts[0] else "XXX"
                return ','.join(parts)
            return "[REDACTED_ADDRESS]"
        elif key in ['ip_address', 'device_id']:
            return "[REDACTED_" + key.upper() + "]"
        
        return value_str
    
    def process_record(self, record_data: Dict) -> Tuple[Dict, bool]:
        """Process a single record for PII detection and redaction"""
        is_pii, pii_fields = self.detect_pii(record_data)
        
        redacted_data = {}
        for key, value in record_data.items():
            if is_pii and (key in pii_fields or 
                          (key in ['first_name', 'last_name'] and 'name_combination' in pii_fields) or
                          (key == 'name' and 'name' in pii_fields) or
                          (key == 'email' and 'email' in pii_fields) or
                          (key == 'address' and 'address' in pii_fields) or
                          (key in ['ip_address', 'device_id'] and key in pii_fields)):
                redacted_data[key] = self.redact_value(key, value)
            else:
                redacted_data[key] = value
        
        return redacted_data, is_pii

def process_dataset():
    detector = PIIDetector()
    df = pd.read_csv('iscp_pii_dataset_-_Sheet1.csv')
    
    results = []
    for index, row in df.iterrows():
        record_id = row['record_id']
        
        try:
            data_json = json.loads(row['data_json'])
            redacted_data, is_pii = detector.process_record(data_json)
            redacted_json = json.dumps(redacted_data)
            
            results.append({
                'record_id': record_id,
                'redacted_data_json': redacted_json,
                'is_pii': is_pii
            })
            
        except json.JSONDecodeError as e:
            print(f"Error parsing JSON for record {record_id}: {e}")
            results.append({
                'record_id': record_id,
                'redacted_data_json': row['data_json'],
                'is_pii': False
            })
    
    output_df = pd.DataFrame(results)
    output_df.to_csv('redacted_output_candidate_full_name.csv', index=False)
    
    print(f"Dataset processed: {len(results)} records")
    print(f"PII detections: {sum(1 for r in results if r['is_pii'])} ({sum(1 for r in results if r['is_pii'])/len(results):.1%})")
    
    return output_df

result_df = process_dataset()