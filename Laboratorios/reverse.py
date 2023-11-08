def verificar_contraseña(entrada_usuario):
    contraseña_secreta = "s3cr3t!"  # Esta es la contraseña que deben encontrar
    return entrada_usuario == contraseña_secreta


def main():
    entrada_usuario = input("Introduce la contraseña: ")
    if verificar_contraseña(entrada_usuario):
        print("¡Contraseña correcta!")
        print("La bandera es FLAG{bien_hecho}")
    else:
        print("Contraseña incorrecta.")


if __name__ == "__main__":
    main()
