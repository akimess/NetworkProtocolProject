import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
 
class Encryption:
  @staticmethod
  def get_key(name, plain=False):
    try:
      key = pgpy.PGPKey.from_file('{}.asc'.format(name))[0]
      return str(key) if plain else key
    except:
      return None
 
  @staticmethod
  def generate_certificates():
    """
    Will create two PGP pairs inside current folder. one named first.asc, second one second.asc 
    NAME will be used as name of the owner.
 
    Both private (key) and public (key.pubkey) keys will be stored in each file.
    """
    NAME = "NetworkProtocol"
    for pair_name in ['first', 'second']:
      key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 2048)
      uid = pgpy.PGPUID.new(NAME)
      key.add_uid(uid, 
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA512],
        ciphers=[PubKeyAlgorithm.RSAEncryptOrSign, SymmetricKeyAlgorithm.AES128],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
      open('{}.asc'.format(pair_name), 'wb').write(bytes(key))
 
  @staticmethod
  def encrypt(data, key='first'):
    k = Encryption.get_key(key)
    m = k.pubkey.encrypt(pgpy.PGPMessage.new(data), cipher=SymmetricKeyAlgorithm.AES128)
    return bytes(m)
 
  @staticmethod
  def decrypt(data, key='first'):
    k = Encryption.get_key(key)
    m = k.decrypt(pgpy.PGPMessage.from_blob(data))
    return bytes(m._message.contents) if isinstance(m._message.contents, bytearray) else m._message.contents



