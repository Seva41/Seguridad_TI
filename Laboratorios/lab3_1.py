def verificar_contraseña(entrada_usuario):
    contraseña_secreta = "s3cr3t!aes128IV0"
    return entrada_usuario == contraseña_secreta


def main():
    entrada_usuario = input("Introduce la contraseña: ")
    if verificar_contraseña(entrada_usuario):
        print("¡Contraseña correcta!")
        print("La bandera cifrada es 4555e2932c17f23b22c977138b391a21")
    else:
        print("Contraseña incorrecta.")


if __name__ == "__main__":
    main()
