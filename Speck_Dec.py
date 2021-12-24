from __future__ import print_function
from random import randint
from time import sleep
import paho.mqtt.client as mqtt
import json
from datetime import datetime

mqttBroker = "192.168.1.152"
client = mqtt.Client("Speck Subscriber")
client.connect(mqttBroker)

class SpeckCipher(object):
    """Speck Block Cipher Object"""
    # valid cipher configurations stored:
    # block_size:{key_size:number_rounds}
    __valid_setups = {32: {64: 22},
                      48: {72: 22, 96: 23},
                      64: {96: 26, 128: 27},
                      96: {96: 28, 144: 29},
                      128: {128: 32, 192: 33, 256: 34}}

    __valid_modes = ['ECB', 'CBC']

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:', [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds and Key Size
        try:
            self.rounds = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:', [x for x in self.possible_setups.keys()])
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Mod mask for modular subtraction
        self.mod_mask_sub = (2 ** self.word_size)

        # Setup Circular Shift Parameters
        if self.block_size == 32:
            self.beta_shift = 2
            self.alpha_shift = 7
        else:
            self.beta_shift = 3
            self.alpha_shift = 8

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** self.block_size) - 1)
            self.iv_upper = self.iv >> self.word_size
            self.iv_lower = self.iv & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** self.block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:', self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        self.key_schedule = [self.key & self.mod_mask]
        l_schedule = [(self.key >> (x * self.word_size)) & self.mod_mask for x in
                      range(1, self.key_size // self.word_size)]

        for x in range(self.rounds - 1):
            new_l_k = self.encrypt_round(l_schedule[x], self.key_schedule[x], x)
            l_schedule.append(new_l_k[0])
            self.key_schedule.append(new_l_k[1])

    def decrypt_round(self, x, y, k):
        """Complete One Round of Inverse Feistel Operation"""

        xor_xy = x ^ y

        new_y = ((xor_xy << (self.word_size - self.beta_shift)) + (xor_xy >> self.beta_shift)) & self.mod_mask

        xor_xk = x ^ k

        msub = ((xor_xk - new_y) + self.mod_mask_sub) % self.mod_mask_sub

        new_x = ((msub >> (self.word_size - self.alpha_shift)) + (msub << self.alpha_shift)) & self.mod_mask

        return new_x, new_y

    def encrypt_round(self, x, y, k):
        """Complete One Round of Feistel Operation"""
        rs_x = ((x << (self.word_size - self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask

        add_sxy = (rs_x + y) & self.mod_mask

        new_x = k ^ add_sxy

        ls_y = ((y >> (self.word_size - self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask

        new_y = new_x ^ ls_y

        return new_x, new_y

    def decrypt(self, ciphertext):
        try:
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid ciphertext!')
            print('Please provide plaintext as int')
            raise

        if self.mode == 'ECB':
            b, a = self.decrypt_function(b, a)

        elif self.mode == 'CBC':
            f, e = b, a
            b, a = self.decrypt_function(b, a)
            b ^= self.iv_upper
            a ^= self.iv_lower

            self.iv_upper = f
            self.iv_lower = e
            self.iv = (f << self.word_size) + e

        plaintext = (b << self.word_size) + a

        return plaintext

    def decrypt_function(self, upper_word, lower_word):

        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule):
            xor_xy = x ^ y

            y = ((xor_xy << (self.word_size - self.beta_shift)) + (xor_xy >> self.beta_shift)) & self.mod_mask

            xor_xk = x ^ k

            msub = ((xor_xk - y) + self.mod_mask_sub) % self.mod_mask_sub

            x = ((msub >> (self.word_size - self.alpha_shift)) + (msub << self.alpha_shift)) & self.mod_mask

        return x, y

    def update_iv(self, new_iv=None):
        if new_iv:
            try:
                self.iv = new_iv & ((2 ** self.block_size) - 1)
                self.iv_upper = self.iv >> self.word_size
                self.iv_lower = self.iv & self.mod_mask
            except TypeError:
                print('Invalid Initialization Vector!')
                print('Please provide IV as int')
                raise
        return self.iv

def pencatatan(msg, dateSend):
	now = str(datetime.now().timestamp())
	f = open('subscribe_Speck.csv', 'a')
	f.write(msg + ";" + now + ";" + dateSend + "\n")

if __name__ == "__main__":
   # key = 0x1f1e1d1c1b1a19181716151413121110 
   # key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a0908
    key = 0x1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100
    cipher = SpeckCipher(key, 256, 128, 'CBC', 0x123456789ABCDEF0)
    def on_message(client, userdata, message):
        raw = json.loads(message.payload.decode("utf-8"))
        msg = int(raw['cipher'])
        dateSend = raw['datetime']
        pencatatan(str(msg), dateSend)
        dec = cipher.decrypt(msg)
        print("Decrypted\t: ", dec)

    client.loop_start()
    client.subscribe("SPECK")
    client.on_message=on_message
    sleep(300)
    client.loop_stop
