from Cryptodome.Cipher import AES
import binascii
from time import sleep
import paho.mqtt.client as mqtt
import ast
from decouple import config

#MQTT
mqttBroker = config('ADDRESS')
client = mqtt.Client("AES Subscriber")
client.connect(mqttBroker)

def add_to_16(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt(data, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    bs = AES.block_size
    pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
    cipher = AES.new(password, AES.MODE_ECB)
    data = cipher.encrypt(pad(data).encode('utf8'))
    encrypt_data = binascii.b2a_hex (data) # Output HEX
         # Encrypt_data = Base64.b64encode (data) #Climinate Comments, Output Base64 Format
    return encrypt_data.decode('utf8')

def decrypt(decrData, password):
    if isinstance(password, str):
        password = password.encode('utf8')
    cipher = AES.new(password, AES.MODE_ECB)
    plain_text = cipher.decrypt(binascii.a2b_hex(decrData))
    return plain_text.decode('utf8').rstrip('\0')

if __name__ == '__main__':
    Password = input("Password: ")
    password = add_to_16(Password)
    def on_message(client, userdata, message):
        msg = message.payload.decode("utf-8")
        decrypted = decrypt(msg, password)
        print("Decrypted\t: ", decrypted[0:15])


    client.loop_start()
    client.subscribe("AES")
    client.on_message=on_message
    sleep(300)
    client.loop_stop
