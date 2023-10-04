#import RSA library
from cryptography.hazmat.backends import default_backend 
from cryptography.hazmat.primitives.asymmetric import rsa
#for hashing and padding for signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# create public and private keys
def generate_keys():
    private = rsa.generate_private_key (
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public = private.public_key()
    return private, public

#For Signing Function
def sign(message, private_key):
    message = bytes(str(message),'utf-8')
    signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    return signature

#verification function
def verify(message,sig, public):
    message = bytes(str(message),'utf-8')
    try:
        public.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except:
        return False
  
#displaying public and private keys
if __name__ == "__main__":
    pr , pu = generate_keys()
    print(pr)
    print(pu)
    message = "Hello world"
    msg="checking"
    #here we can pass message variable to the sign function but in the verify function we add msg variable which is change message, so it will be faild
    sig=sign(message,pr)
    print("sign message ",sig)
    #third step to verify the sig
    correct=verify(message,sig,pu)
    if correct:
        print("successful")
        #print("",verify(message,sig, pu))
    else: 
        print("Failed")