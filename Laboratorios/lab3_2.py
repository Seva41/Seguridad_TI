def verificar_contraseña(entrada_usuario):
    contraseña_secreta = "s3cr3t!aes128IV1"
    return entrada_usuario == contraseña_secreta


def main():
    entrada_usuario = input("Introduce la contraseña: ")
    if verificar_contraseña(entrada_usuario):
        print("¡Contraseña correcta!")
        print("La bandera cifrada es f5084c8ddabfabfb9ea2a4ee145cdeea")
    else:
        print("Contraseña incorrecta.")


if __name__ == "__main__":
    main()
