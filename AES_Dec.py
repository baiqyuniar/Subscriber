import Cryptodome.Cipher.AES
import Cryptodome.Random
import base64
import binascii
from time import sleep
import paho.mqtt.client as mqtt
import json
from datetime import datetime

# MQTT Initializing
mqttBroker = "192.168.10.108"
client = mqtt.Client('AES Subscriber')
client.connect(mqttBroker)

class Cipher_AES:
	unpad_default = lambda x: x.rstrip()		# Method untuk menghilangkan default padding
	unpad_pkcs5 = lambda x: x[:-ord(x[-1])]		# Method untuk menghilangkan pkcd5 padding

	# Set IV dan key
	def __init__(self, key, iv):
		self.__key = key
		self.__iv = iv

	# Mode ECB
	def Cipher_MODE_ECB(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_ECB)

	# Mode CBC
	def Cipher_MODE_CBC(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_CBC,
										 self.__iv.encode("utf-8"))

	# Menjalankan proses dekripsi. Inputan berupa (Cipher text, Metode enkripsi, Metode padding, Metode decode)
	def decrypt(self, cipher_text, cipher_method, unpad_method="", code_method=""):

		# Pemilihan mode ECB atau CBC
		if cipher_method.upper() == "MODE_ECB":
			self.Cipher_MODE_ECB()
		elif cipher_method.upper() == "MODE_CBC":
			self.Cipher_MODE_CBC()

		# Pemilihan metode decode
		if code_method.lower() == "base64":
			cipher_text = base64.decodebytes(cipher_text.encode("utf-8"))
		elif code_method.lower() == "hex":
			cipher_text = binascii.a2b_hex(cipher_text.encode("utf-8"))
		else:
			cipher_text = cipher_text.encode("utf-8")

		# Proses dekripsi
		return self.unpad_method(self.__x.decrypt(cipher_text).decode("utf-8"), unpad_method)

	# Pemilihan metode unpadding sehingga menghasilkan text aslinya
	def unpad_method(self, text, method):
		if method == "":
			return Cipher_AES.unpad_default(text)
		elif method == "PKCS5Padding":
			return Cipher_AES.unpad_pkcs5(text)
	
def main(msg):
	key = "Mu8weQyDvq1HlAzNMu8weQyDvq1HlAzN"
	iv = "HIwu5283JGHsi76H" 
	cipher_method = "MODE_CBC"
	unpad_method = "PKCS5Padding"
	code_method = "base64"
	text = Cipher_AES(key, iv).decrypt(msg, cipher_method, unpad_method, code_method)
	print('Decrypted\t:' + text)

# Melakukan pencatatan ke dalam file .csv
def pencatatan(msg, dateSend):
	now = str(datetime.now().timestamp())
	f = open('subscribe_AES.csv', 'a')
	f.write(msg + ";" + now + ";" + dateSend + "\n")

if __name__ == '__main__':
	def on_message(client, userdata, message):
		raw = json.loads(message.payload.decode('utf-8'))		# Mengubah string menjadi JSON
		msg = raw['cipher']										# Mengambil value dari cipher
		dateSend = raw['datetime']								# Mengambil value dari datetime
		pencatatan(msg, dateSend)
		main(msg)


	client.loop_start()
	client.subscribe('AES')
	client.on_message=on_message								# Listening jika ada message baru di broker dengan topik yang sama
	sleep(700)
	client.loop_stop
