#!/usr/bin/env python3
"""
Wazuh Email Report Sender
Virtual Enterprise Cybersecurity Lab - Phase 4.6

Günlük raporu HTML email olarak gönderir.
"""

import smtplib
import ssl
import os
import sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime
from pathlib import Path


class EmailReporter:
    """Email raporu gönderici"""
    
    def __init__(self, smtp_server, smtp_port, username, password):
        """
        Args:
            smtp_server: SMTP sunucu (örn: smtp.gmail.com)
            smtp_port: SMTP port (587 = STARTTLS, 465 = SSL)
            username: Email adresi
            password: App password
        """
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
    
    def send_report(self, to_email, subject, html_body, attachment_path=None):
        """Email gönder"""
        
        # Email oluştur
        msg = MIMEMultipart('alternative')
        msg['From'] = self.username
        msg['To'] = to_email
        msg['Subject'] = subject
        msg['Date'] = datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z')
        
        # HTML gövde
        html_part = MIMEText(html_body, 'html', 'utf-8')
        msg.attach(html_part)
        
        # Ek dosya (opsiyonel)
        if attachment_path and os.path.exists(attachment_path):
            with open(attachment_path, 'rb') as f:
                attachment = MIMEApplication(f.read(), _subtype='html')
                attachment.add_header(
                    'Content-Disposition',
                    'attachment',
                    filename=os.path.basename(attachment_path)
                )
                msg.attach(attachment)
        
        # SMTP bağlantısı
        context = ssl.create_default_context()
        
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.send_message(msg)
            return True, "Email sent successfully"
        except Exception as e:
            return False, f"Error: {e}"


def build_email_body(report_html_path):
    """HTML raporunu email gövdesine dönüştür"""
    
    if not os.path.exists(report_html_path):
        # Fallback: basit HTML
        return f"""
        <html>
        <body style="font-family: sans-serif;">
            <h2> Wazuh Günlük Güvenlik Raporu</h2>
            <p><strong>Tarih:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            <p>HTML rapor dosyası bulunamadı: {report_html_path}</p>
        </body>
        </html>
        """
    
    with open(report_html_path, 'r', encoding='utf-8') as f:
        return f.read()


def main():
    """Ana fonksiyon"""
    
    # === KONFİGÜRASYON ===
    # Bu bilgileri kendine göre değiştir!
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    SENDER_EMAIL = "beratates394@gmail.com"
    SENDER_PASSWORD = "mpih ekeg jlpq wnwt"  # Gmail App Password (16 haneli)
    RECIPIENT_EMAIL = "beratates394@gmail.com"  # Aynı adrese gönder (test)
    
    # Rapor dizini
    report_dir = os.path.expanduser("~/cybersecurity-lab/phase-04-automation/reports")
    today = datetime.now().strftime("%Y-%m-%d")
    html_report = os.path.join(report_dir, f"daily_{today}.html")
    
    print("=" * 70)
    print("Wazuh Email Report Sender")
    print("=" * 70)
    print(f"Time: {datetime.now().isoformat()}")
    print(f"SMTP Server: {SMTP_SERVER}:{SMTP_PORT}")
    print(f"From: {SENDER_EMAIL}")
    print(f"To: {RECIPIENT_EMAIL}")
    print()
    
    # HTML raporu kontrol et
    if not os.path.exists(html_report):
        print(f" HTML report not found: {html_report}")
        print("  Generating fresh report...")
        
        # Rapor üret
        from generate_daily_report import main as generate_main
        try:
            generate_main()
        except:
            pass
    
    # Email gövdesi
    html_body = build_email_body(html_report)
    
    # Email konusu
    subject = f" Wazuh Günlük Güvenlik Raporu - {today}"
    
    # Email gönder
    print("[1] Sending email...")
    reporter = EmailReporter(SMTP_SERVER, SMTP_PORT, SENDER_EMAIL, SENDER_PASSWORD)
    success, message = reporter.send_report(
        RECIPIENT_EMAIL,
        subject,
        html_body,
        attachment_path=html_report
    )
    
    if success:
        print(f"     {message}")
        print()
        print("=" * 70)
        print(" Email sent successfully")
        print("=" * 70)
        return 0
    else:
        print(f"     {message}")
        print()
        print("=" * 70)
        print(" Email sending FAILED")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
