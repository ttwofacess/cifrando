function validarClave(clave) {
    // Mínimo 12 caracteres, al menos: 1 mayúscula, 1 minúscula, 1 número y 1 símbolo
        const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{12,}$/;
        return regex.test(clave);
    }

    // Event listener para mostrar fortaleza de la clave
    document.getElementById("secretKey").addEventListener("input", function() {
        const password = this.value;
        const strengthBar = document.getElementById("passwordStrength");
        const strengthText = document.getElementById("strengthText");
        
        // Reset classes
        strengthBar.className = "";
        
        // Calcular puntaje de fortaleza
        let score = 0;
        
        // Longitud mínima
        if (password.length >= 12) score++;
        // Contiene mayúsculas
        if (/[A-Z]/.test(password)) score++;
        // Contiene minúsculas
        if (/[a-z]/.test(password)) score++;
        // Contiene números
        if (/\d/.test(password)) score++;
        // Contiene símbolos
        if (/[^a-zA-Z0-9]/.test(password)) score++;
        
        // Ajustar score máximo a 4 (para nuestras 5 clases CSS)
        score = Math.min(4, score);
        
        // Aplicar clase y texto según score
        strengthBar.classList.add(`strength-${score}`);
        
        const strengthLabels = ["Muy débil", "Débil", "Moderada", "Fuerte", "Muy fuerte"];
        strengthText.textContent = `Seguridad: ${strengthLabels[score]}`;
        strengthText.style.color = ["#ff4d4d", "#ff8c66", "#ffcc00", "#66cc66", "#00b300"][score];
    });

    function cifrar() {
        let texto = document.getElementById("inputText").value;
        let claveSecreta = document.getElementById("secretKey").value;

        
        if (!texto || !claveSecreta) {
            alert("Ingresa tanto el texto como la clave secreta");
            return;
        }

        // Validar fortaleza de la clave
        if (!validarClave(claveSecreta)) {
            alert("La clave debe tener al menos 12 caracteres e incluir mayúsculas, minúsculas, números y símbolos");
            return;
        }

        const salt = CryptoJS.lib.WordArray.random(128/8);
        const iteraciones = 10000;
        const claveDerivada = CryptoJS.PBKDF2(claveSecreta, salt, {
            keySize: 256/32,
            iterations: iteraciones
        });
        
        const iv = CryptoJS.lib.WordArray.random(128/8);
        const cifrado = CryptoJS.AES.encrypt(texto, claveDerivada, { 
            iv: iv,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        
        // Combinar salt, iv y texto cifrado para almacenamiento/transmisión
        const resultado = salt.toString() + iv.toString() + cifrado.toString();
        document.getElementById("outputText").value = resultado;
    }

    let intentosFallidos = 0;
    const MAX_INTENTOS = 5;

    function descifrar() {
        const inicio = Date.now();
        let textoCifrado = document.getElementById("inputText").value;
        let claveSecreta = document.getElementById("secretKey").value;

        if (!textoCifrado || !claveSecreta) {
            alert("Ingresa tanto el texto cifrado como la clave secreta");    
            return;
        }

        if (!validarClave(claveSecreta)) {
            alert("La clave debe tener al menos 12 caracteres e incluir mayúsculas, minúsculas, números y símbolos");
            return;
        }

        try {
                // Verificar longitud mínima del texto cifrado (salt + iv = 64 caracteres hex)
            if (textoCifrado.length < 64) {
                alert("El texto cifrado no tiene el formato correcto");
                return;
            }

            // Extraer componentes (salt: 32 chars hex, iv: 32 chars hex, resto: texto cifrado)
            const salt = CryptoJS.enc.Hex.parse(textoCifrado.substr(0, 32));
            const iv = CryptoJS.enc.Hex.parse(textoCifrado.substr(32, 32));
            const textoCifradoReal = textoCifrado.substring(64);

            // Derivar clave usando PBKDF2
            const iteraciones = 10000;
            const claveDerivada = CryptoJS.PBKDF2(claveSecreta, salt, {
                keySize: 256/32,
                iterations: iteraciones
            });

            // Descifrar usando AES-CBC
            const bytes = CryptoJS.AES.decrypt(textoCifradoReal, claveDerivada, {
                iv: iv,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });

            // Convertir a texto plano
            const textoDescifrado = bytes.toString(CryptoJS.enc.Utf8);

            // --- INICIO del bloque de control de intentos fallidos ---
            if (!textoDescifrado) {
                intentosFallidos++;
                if (intentosFallidos >= MAX_INTENTOS) {
                    alert("Demasiados intentos fallidos. Por favor, recarga la página.");
                    return;
                }
                alert(`Clave incorrecta. Intentos restantes: ${MAX_INTENTOS - intentosFallidos}`);
                return;
            }
            intentosFallidos = 0; // Resetear contador si es exitoso
            // --- FIN del bloque ---

            // Mostrar resultado
            document.getElementById("outputText").value = textoDescifrado;
            
        } catch (error) {
            console.error("Error al descifrar:", error);
            alert("Error al descifrar. Verifica el texto cifrado y la clave.");
        } 

        const tiempoTranscurrido = Date.now() - inicio;
        const retardoMinimo = 500; // 500ms
        if (tiempoTranscurrido < retardoMinimo) {
            setTimeout(() => {
                // Continuar con el proceso o mostrar error
            }, retardoMinimo - tiempoTranscurrido);
        }
    }