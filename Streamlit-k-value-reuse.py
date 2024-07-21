import hashlib
import secrets
import ecdsa #0.18.0
from ecdsa import SECP256k1, ellipticcurve
import streamlit as st
import time

@st.cache_data()
def generate_keys():
    """Generates a private key."""
    private_key = secrets.randbits(256)
    sk = ecdsa.SigningKey.from_string(private_key.to_bytes(32, "big"), SECP256k1)
    sk_int = int.from_bytes(sk.to_string(), "big")
    generator_point = ellipticcurve.Point(SECP256k1.curve, SECP256k1.generator.x(), SECP256k1.generator.y(), SECP256k1.order)
    return sk, generator_point, sk_int

@st.cache_data()
def generate_k_value():
    return secrets.randbelow(SECP256k1.order)


def hash_message(message):
    """Hashes a message using SHA-256."""
    return hashlib.sha256(message.encode('utf-8')).digest()


def sign_message(private_key, message_hash, generator_point, random_key):
    """Signs a message."""
    R = random_key * generator_point
    r = R.x() % SECP256k1.order
    sk_int = int.from_bytes(private_key.to_string(), "big")
    message_hash_int = int.from_bytes(message_hash, "big")
    s = (pow(random_key, -1, SECP256k1.order) * (message_hash_int + sk_int * r)) % SECP256k1.order
    return r, s, message_hash_int


def k_value_extraction(h1, h2, svalue1, svalue2):
    """Extracts the value of k used in ECDSA signing based on two message hashes and corresponding signature values."""
    s_diff_inv = pow((svalue1 - svalue2) % SECP256k1.order, -1, SECP256k1.order)
    return ((h1 - h2) % SECP256k1.order * s_diff_inv) % SECP256k1.order


def sk_value_extraction(rvalue, svalue1, kvalue, h1):
    """Extracts the private key used in ECDSA signing based on signature values, message hash, and the value of k."""
    r_inv = pow(rvalue, -1, SECP256k1.order)
    return ((((svalue1*kvalue) % SECP256k1.order - h1) % SECP256k1.order) * r_inv) % SECP256k1.order


if __name__ == "__main__":


    st.title('k Value Reuse')

    # Generar clave privada y valor k
    sk, g, sk_int = generate_keys()
    random_key = generate_k_value()
    st.write(f"Clave Privada:\n {sk.to_string().hex()}")
    st.write(f"Valor k: {hex(random_key)[2:]}")

    # Inicializa session_state si no está inicializado
    if 'signature1' not in st.session_state:
        st.session_state.signature1 = None

    if 'signature2' not in st.session_state:
        st.session_state.signature2 = None

    if 'message_hash1' not in st.session_state:
        st.session_state.message_hash1 = None

    if 'message_hash2' not in st.session_state:
        st.session_state.message_hash2 = None

    # Primer mensaje
    st.write("Primer Mensaje a Firmar")
    message = st.text_input("Introduce el primer mensaje a firmar:", key='message1')
    message_hash = hash_message(message)
    k_input_st = st.text_input("Introduce el valor de k para el primer mensaje:", key='k_input1')

    # Imprime el valor de k_input_st para depuración
    #st.write(f"Valor de k_input_st recibido para el primer mensaje: '{k_input_st}'")

    # Limpia espacios en blanco alrededor del valor de k
    k_input_st = k_input_st.strip()

    if k_input_st:
        try:
            # Convierte el valor a entero en base 16
            k_inputed_1 = int(k_input_st, 16)
            if st.button("Firmar Primer Mensaje"):
                r, s, messagehashint1 = sign_message(sk, message_hash, g, k_inputed_1)
                st.session_state.signature1 = (r, s)  # Guarda la firma en session_state
                st.session_state.message_hash1 = int.from_bytes(message_hash, 'big')  # Guarda el hash del mensaje como entero
                #st.write(f"Firma Primer Mensaje: (r= {hex(r)[2:]}, s= {hex(s)[2:]})")
        except ValueError as e:
            # Muestra el error de conversión para depuración
            st.write(f"Error al convertir el valor de k para el primer mensaje: {e}")
    else:
        if st.button("Firmar Primer Mensaje"):
            st.write("Por favor, introduce un valor para k.")

    # Mostrar la firma del primer mensaje si está disponible
    if st.session_state.signature1:
        r, s = st.session_state.signature1
        st.write(f"Firma del Primer Mensaje: (r= {hex(r)[2:]}, s= {hex(s)[2:]})")

    # Segundo mensaje
    st.write("Segundo Mensaje a Firmar")
    message2 = st.text_input("Introduce el segundo mensaje a firmar:", key='message2')
    message_hash2 = hash_message(message2)
    k_input_st2 = st.text_input("Introduce el valor de k para el segundo mensaje:", key='k_input2')

    # Imprime el valor de k_input_st2 para depuración
    #st.write(f"Valor de k_input_st recibido para el segundo mensaje: '{k_input_st2}'")

    # Limpia espacios en blanco alrededor del valor de k
    k_input_st2 = k_input_st2.strip()

    if k_input_st2:
        try:
            # Convierte el valor a entero en base 16
            k_inputed_2 = int(k_input_st2, 16)
            if st.button("Firmar Segundo Mensaje"):
                r2, s2, messagehashint2 = sign_message(sk, message_hash2, g, k_inputed_2)
                st.session_state.signature2 = (r2, s2)  # Guarda la firma en session_state
                st.session_state.message_hash2 = int.from_bytes(message_hash2, 'big')  # Guarda el hash del segundo mensaje como entero
                #st.write(f"Firma Segundo Mensaje: (r= {hex(r2)[2:]}, s= {hex(s2)[2:]})")
        except ValueError as e:
            # Muestra el error de conversión para depuración
            st.write(f"Error al convertir el valor de k para el segundo mensaje: {e}")
    else:
        if st.button("Firmar Segundo Mensaje"):
            st.write("Por favor, introduce un valor para k.")

    # Mostrar la firma del segundo mensaje si está disponible
    if st.session_state.signature2:
        r2, s2 = st.session_state.signature2
        st.write(f"Firma del Segundo Mensaje: (r2= {hex(r2)[2:]}, s2= {hex(s2)[2:]})")

    # Extracción y verificación
    if st.session_state.signature1 and st.session_state.signature2:
        r, s = st.session_state.signature1
        r2, s2 = st.session_state.signature2
        messagehashint1 = st.session_state.message_hash1
        messagehashint2 = st.session_state.message_hash2

        st.write("\nEXTRACCIÓN DE K Y CLAVE PRIVADA")

        # La función k_value_extraction espera enteros para los hashes
        extractedK = k_value_extraction(messagehashint1, messagehashint2, s, s2)
        if extractedK == random_key:
            st.write("\nEl valor de k se ha extraído correctamente utilizando ambas firmas y mensajes.")
        else:
            st.write("\nNO, los valores no son iguales.")
        st.write(f"Tu valor de k era= {hex(random_key)[2:]}")
        st.write(f"Valor k extraído= {hex(extractedK)[2:]}")

        # La función sk_value_extraction espera enteros para los valores
        extractedSk = sk_value_extraction(r, s, extractedK, messagehashint1)
        if extractedSk == sk_int:
            st.write("\nEl valor de tu clave privada se ha extraído correctamente.")
        else:
            st.write("\nNO, los valores no son iguales.")
        st.write(f"Tu Clave Privada era= {sk.to_string().hex()}")
        st.write(f"Clave Extraída= {hex(extractedSk)[2:]}")

        if extractedSk == sk_int:
            st.write("\nY POR ESO NUNCA DEBES USAR EL MISMO VALOR K DOS VECES.")
