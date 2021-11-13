import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64


recievers = "florian.zettl@gmx.net"


msg = MIMEText("""Lieber Kunde,
Bitte bestätigen Sie das Kontopasswort, um eine bessere Servicekommunikation zu ermöglichen, und vermeiden Postzustellungsfehlfunktion
Hinweis: T-Online.de ist nicht verantwortlich für Online-Diebstahl oder Mail-Fehlfunktion nach dieser Warnung und keine Verifizierantwort.
        
Danke und Grüße,
T-Online.de (C) 2019 Gesichererter Dienst.
============================================================
Bitte antworten Sie nicht auf diese Email.
Dieses automatische Postfach wird incht überwacht und Sie erhalten keine Antwor""")

msg['From'] = "info@t-online.de"
msg['To'] = reciever
msg['Subject'] = "Achtung: E-Mail Kontoinhaber"


server = smtplib.SMTP('localhost:25')
    
server.starttls()

server.sendmail('info@t-online.de', reciever, msg.as_string())
server.quit()
