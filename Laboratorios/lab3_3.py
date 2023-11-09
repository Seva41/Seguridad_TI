def verificar_contraseña(entrada_usuario):
    contraseña_secreta = "s3cr3t!aes128IV2"
    return entrada_usuario == contraseña_secreta


def main():
    entrada_usuario = input("Introduce la contraseña: ")
    if verificar_contraseña(entrada_usuario):
        print("¡Contraseña correcta!")
        print("La bandera cifrada es 936fff953d6dbc0f4899e06319ec6565")
    else:
        print("Contraseña incorrecta.")


if __name__ == "__main__":
    main()
