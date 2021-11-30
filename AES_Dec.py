import Cryptodome.Cipher.AES
import Cryptodome.Random
import base64
import binascii
from time import sleep
import paho.mqtt.client as mqtt
import json

# MQTT
mqttBroker = "192.168.8.171"
client = mqtt.Client('AES Subscriber')
client.connect(mqttBroker)

class Cipher_AES:
	pad_default = lambda x, y: x + (y - len(x) % y) * " ".encode("utf-8")
	unpad_default = lambda x: x.rstrip()
	pad_user_defined = lambda x, y, z: x + (y - len(x) % y) * z.encode("utf-8")
	unpad_user_defined = lambda x, z: x.rstrip(z)
	pad_pkcs5 = lambda x, y: x + (y - len(x) % y) * chr(y - len(x) % y).encode("utf-8")
	unpad_pkcs5 = lambda x: x[:-ord(x[-1])]

	def __init__(self, key="abcdefgh12345678", iv=Cryptodome.Random.new().read(Cryptodome.Cipher.AES.block_size)):
		self.__key = key
		self.__iv = iv

	def set_key(self, key):
		self.__key = key

	def get_key(self):
		return self.__key

	def set_iv(self, iv):
		self.__iv = iv

	def get_iv(self):
		return self.__iv

	def Cipher_MODE_ECB(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_ECB)

	def Cipher_MODE_CBC(self):
		self.__x = Cryptodome.Cipher.AES.new(self.__key.encode("utf-8"), Cryptodome.Cipher.AES.MODE_CBC,
										 self.__iv.encode("utf-8"))

	def decrypt(self, cipher_text, cipher_method, pad_method="", code_method=""):
		if cipher_method.upper() == "MODE_ECB":
			self.Cipher_MODE_ECB()
		elif cipher_method.upper() == "MODE_CBC":
			self.Cipher_MODE_CBC()
		if code_method.lower() == "base64":
			cipher_text = base64.decodebytes(cipher_text.encode("utf-8"))
		elif code_method.lower() == "hex":
			cipher_text = binascii.a2b_hex(cipher_text.encode("utf-8"))
		else:
			cipher_text = cipher_text.encode("utf-8")
		return self.unpad_method(self.__x.decrypt(cipher_text).decode("utf-8"), pad_method)

	def pad_method(self, text, method):
		if method == "":
			return Cipher_AES.pad_default(text, len(self.__key))
		elif method == "PKCS5Padding":
			return Cipher_AES.pad_pkcs5(text, len(self.__key))
		else:
			return Cipher_AES.pad_user_defined(text, len(self.__key), method)

	def unpad_method(self, text, method):
		if method == "":
			return Cipher_AES.unpad_default(text)
		elif method == "PKCS5Padding":
			return Cipher_AES.unpad_pkcs5(text)
		else:
			return Cipher_AES.unpad_user_defined(text, method)

	
def main2(msg, token):
	st_arr = []
	dy_arr = []
	static_str = 'Mu8weQyDvq1HlAzN'
	for b in bytearray(static_str, "utf-8"):
		st_arr.append(b)

	token_str = token[-16:]
	for b in bytearray(token_str, "utf-8"):
		dy_arr.append(b)

	res_byts = []
	for bt in bytes(a ^ b for (a, b) in zip(st_arr, dy_arr)):
		res_byts.append(bt)

	key = bytes(res_byts).decode()
	iv = key 
	cipher_method = "MODE_CBC"
	pad_method = "PKCS5Padding"
	code_method = "base64"
	text = Cipher_AES(key, iv).decrypt(msg, cipher_method, pad_method, code_method)
	print('Decrypted\t:' + text)

if __name__ == '__main__':
    def on_message(client, userdata, message):
        raw = json.loads(message.payload.decode('utf-8'))
		# mess = raw['cipher']
        main2(raw['cipher'], "CI6MTU3ODQ4ODYyM30.SAjMKd0chcAWoFwMkfxJ-Z1lWRM9-AeSXuHZiXBTYyo")

    client.loop_start()
    client.subscribe('AES')
    client.on_message=on_message
    sleep(300)
    client.loop_stop