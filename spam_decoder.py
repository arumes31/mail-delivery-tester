import re
import datetime
from email.utils import parsedate_to_datetime

# --- Comprehensive Lookup Tables ---

# Microsoft / Office 365
MS_BCL = {
    0: ('Not bulk', 'success'),
    1: ('Low complaint bulk', 'warning'), 2: ('Low complaint bulk', 'warning'), 3: ('Low complaint bulk', 'warning'),
    4: ('Mixed complaint bulk', 'danger'), 5: ('Mixed complaint bulk', 'danger'), 6: ('Mixed complaint bulk', 'danger'), 7: ('Mixed complaint bulk', 'danger'),
    8: ('High complaint bulk', 'danger'), 9: ('High complaint bulk', 'danger'),
}

MS_SCL = {
    -1: ('Bypassed/Whitelisted', 'success'),
    0: ('Clean', 'success'),
    1: ('Clean', 'success'),
    5: ('Spam', 'danger'),
    6: ('Spam', 'danger'),
    9: ('High Confidence Spam', 'danger'),
}

MS_PCL = {
    1: ('Clean', 'success'), 2: ('Clean', 'success'), 3: ('Clean', 'success'),
    4: ('Phishing suspected', 'danger'), 8: ('High Confidence Phishing', 'danger'),
}

MS_CAT = {
    'BULK': 'Bulk', 'DIMP': 'Domain Impersonation', 'GIMP': 'Mailbox Intelligence Impersonation',
    'HPHISH': 'High Confidence Phishing', 'HSPM': 'High Confidence Spam', 'MALW': 'Malware',
    'PHSH': 'Phishing', 'SPM': 'Spam', 'SPOOF': 'Spoofing', 'NONE': 'Clean',
}

MS_SFV = {
    'BLK': 'Blocked by user', 'NSPM': 'Marked as non-spam', 'SFE': 'Safe sender list',
    'SKA': 'Allowed by policy', 'SKB': 'Blocked by policy', 'SPM': 'Marked as spam',
}

# Anti-Spam Rules (Reverse Engineered IDs)
MS_RULES = {
    '35100500006': 'Embedded image in message',
    '162623004': 'Suspicious words in subject',
    '19618925003': 'Suspicious words in body',
    '30864003': 'Large message body (>10k chars)',
    '67856001': 'HTML underline tag usage',
    '166002': 'HTML contains <a> link',
    '966005': 'URL Masking (href vs text mismatch)',
}

def get_status(val, mapping):
    desc, status = mapping.get(val, (f'Unknown ({val})', 'info'))
    return desc, status

class SpamDecoder:
    def __init__(self, headers):
        # Normalize headers to lowercase keys
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.findings = []

    def decode(self):
        # 1. Microsoft Anti-Spam
        self._test_microsoft_antispam()
        
        # 2. SpamAssassin
        self._test_spamassassin()
        
        # 3. Authentication Headers (SPF/DKIM/DMARC details)
        self._test_auth_results()
        
        # 4. Security Appliances (Mimecast, Proofpoint, etc)
        self._test_security_appliances()
        
        # 5. Heuristics
        self._test_heuristics()
        
        return self.findings

    def _add(self, label, value, status='info'):
        self.findings.append({'label': label, 'value': value, 'status': status})

    def _test_microsoft_antispam(self):
        # X-Forefront-Antispam-Report
        far = self.headers.get('x-forefront-antispam-report', '')
        if far:
            parts = {p.split(':')[0]: p.split(':')[1] for p in far.split(';') if ':' in p}
            if 'SCL' in parts:
                desc, status = get_status(int(parts['SCL']), MS_SCL)
                self._add('O365 SCL', desc, status)
            if 'CAT' in parts:
                self._add('O365 Category', MS_CAT.get(parts['CAT'], parts['CAT']), 'danger' if parts['CAT'] != 'NONE' else 'success')
            if 'SFV' in parts:
                self._add('O365 Filtering', MS_SFV.get(parts['SFV'], parts['SFV']), 'success' if 'S' in parts['SFV'] else 'danger')

        # X-Microsoft-Antispam (BCL/PCL)
        msas = self.headers.get('x-microsoft-antispam', '')
        if msas:
            if 'BCL:' in msas:
                try:
                    bcl = int(msas.split('BCL:')[1].split(';')[0])
                    desc, status = get_status(bcl, MS_BCL)
                    self._add('O365 BCL', desc, status)
                except: pass
            if 'PCL:' in msas:
                try:
                    pcl = int(msas.split('PCL:')[1].split(';')[0])
                    desc, status = get_status(pcl, MS_PCL)
                    self._add('O365 PCL', desc, status)
                except: pass

    def _test_spamassassin(self):
        status = self.headers.get('x-spam-status', '')
        if status:
            is_spam = status.lower().startswith('yes')
            score_match = re.search(r'score=([0-9\.-]+)', status)
            score = score_match.group(1) if score_match else '?'
            self._add('SpamAssassin', f"Score: {score}", 'danger' if is_spam else 'success')

    def _test_auth_results(self):
        auth = self.headers.get('authentication-results', '')
        if auth:
            if 'spf=pass' in auth.lower(): self._add('SPF Auth', 'Pass', 'success')
            elif 'spf=fail' in auth.lower(): self._add('SPF Auth', 'Fail', 'danger')
            
            if 'dkim=pass' in auth.lower(): self._add('DKIM Auth', 'Pass', 'success')
            elif 'dkim=fail' in auth.lower(): self._add('DKIM Auth', 'Fail', 'danger')

            if 'dmarc=pass' in auth.lower(): self._add('DMARC Auth', 'Pass', 'success')
            elif 'dmarc=fail' in auth.lower(): self._add('DMARC Auth', 'Fail', 'danger')

    def _test_security_appliances(self):
        # Mimecast
        if 'x-mimecast-spam-score' in self.headers:
            score = self.headers['x-mimecast-spam-score']
            self._add('Mimecast Score', score, 'warning' if float(score) > 3 else 'success')
        
        # Proofpoint
        if 'x-proofpoint-spam-details' in self.headers:
            details = self.headers['x-proofpoint-spam-details']
            score_match = re.search(r'score=([0-9]+)', details)
            if score_match:
                self._add('Proofpoint Score', score_match.group(1), 'info')

        # Barracuda
        if 'x-barracuda-spam-score' in self.headers:
            self._add('Barracuda Score', self.headers['x-barracuda-spam-score'], 'info')

    def _test_heuristics(self):
        # 1. Domain Impersonation (Simple)
        mail_from = self.headers.get('from', '')
        reply_to = self.headers.get('reply-to', '')
        if mail_from and reply_to:
            from_domain = mail_from.split('@')[-1].strip('>')
            reply_domain = reply_to.split('@')[-1].strip('>')
            if from_domain != reply_domain:
                self._add('Heuristic', f'Reply-to domain mismatch ({reply_domain})', 'warning')

        # 2. X-Mailer / User-Agent
        mailer = self.headers.get('x-mailer') or self.headers.get('user-agent')
        if mailer:
            self._add('Mailer', mailer, 'info')

        # 3. Transport Latency
        date_hdr = self.headers.get('date')
        if date_hdr:
            try:
                sent_dt = parsedate_to_datetime(date_hdr)
                # We don't have 'received' time here, but we can detect old messages
                age = (datetime.datetime.now(datetime.timezone.utc) - sent_dt).total_seconds()
                if age > 3600:
                    self._add('Latency', f'Message is {int(age/60)}m old', 'warning')
            except: pass

def decode_spam_headers(headers_dict):
    decoder = SpamDecoder(headers_dict)
    return decoder.decode()