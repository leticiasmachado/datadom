import re
from collections import Counter
import math

class LexicalFeatures:
    def __init__(self, domain):
        self.domain = domain
        self.vowels = "aeiouAEIOU"
        self.consonants = "bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ"
        self.digits = "0123456789"
        self.special_chars = "!@#$%^&*()-_=+[]{}|;:'\",<>?/~`"

    def get_strange_characters(self):
        return sum(1 for char in self.domain if not char.isalnum() and char not in '-.')

    def get_consonant_ratio(self):
        num_consonants = sum(1 for char in self.domain if char in self.consonants)
        domain_length = len(self.domain)
        return num_consonants / domain_length if domain_length > 0 else 0

    def get_vowel_ratio(self):
        num_vowels = sum(1 for char in self.domain if char in self.vowels)
        domain_length = len(self.domain)
        return num_vowels / domain_length if domain_length > 0 else 0

    def get_numeric_ratio(self):
        num_digits = sum(1 for char in self.domain if char in self.digits)
        domain_length = len(self.domain)
        return num_digits / domain_length if domain_length > 0 else 0

    def get_special_char_ratio(self):
        num_special_chars = sum(1 for char in self.domain if char in self.special_chars)
        domain_length = len(self.domain)
        return num_special_chars / domain_length if domain_length > 0 else 0

    def get_consonant_sequence(self):
        return re.findall(f'[{self.consonants}]+', self.domain)

    def get_vowel_sequence(self):
        return re.findall(f'[{self.vowels}]+', self.domain)

    def get_numeric_sequence(self):
        return re.findall(f'[{self.digits}]+', self.domain)

    def get_special_char_sequence(self):
        return re.findall(f'[{re.escape(self.special_chars)}]+', self.domain)

    def get_domain_length(self):
        return len(self.domain)

    def calculate_entropy(self):
        char_count = Counter(self.domain)
        total_chars = len(self.domain)
        entropy = 0.0
        for count in char_count.values():
            p_x = count / total_chars
            entropy += -p_x * math.log2(p_x)
        return entropy
