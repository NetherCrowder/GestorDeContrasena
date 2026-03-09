"""
security_audit.py - Motor de auditoría para evaluar la salud de las contraseñas.
"""

from datetime import datetime
import json
from utils.helpers import password_strength

# Categorías de alto riesgo que requieren rotación más frecuente
HIGH_RISK_CATEGORIES = [1, 3, 6]  # Banca y Finanzas, Trabajo, Email (según models.py)

class PasswordAuditEngine:
    """Motor de análisis de seguridad para contraseñas individuales y el vault completo."""

    @staticmethod
    def evaluate_health(password: str, username: str, title: str, category_id: int, 
                        updated_at: str, rules_json: str) -> dict:
        """
        Evalúa una contraseña individual y retorna un reporte de vulnerabilidades.
        """
        vulnerabilities = []
        score_impact = 0
        
        try:
            rules = json.loads(rules_json) if rules_json else {}
        except:
            rules = {}

        is_pin = rules.get("pin_only", False)
        
        # Inferencia: si es puramente numérico y corto (<= 8), tratar como PIN
        # para asegurar consistencia entre manual y generador.
        if not is_pin and password.isdigit() and len(password) <= 8:
            is_pin = True
        
        # 1. Análisis de Fortaleza (solo si no es PIN)
        if not is_pin:
            strength_score, label = password_strength(password)
            # Threshold más alto para banca (70) que para el resto (55)
            threshold = 70 if category_id == 1 else 55
            
            if strength_score < threshold:
                # Si es banca, somos un poco más estrictos con el mensaje
                msg = f"Contraseña {label.lower()} ({strength_score}%)."
                if category_id == 1 and strength_score < 70:
                    msg = f"Contraseña bancaria vulnerable ({strength_score}%). Se recomienda mayor complejidad."
                
                vulnerabilities.append({
                    "type": "weak",
                    "severity": "high" if strength_score < 40 else "medium",
                    "message": msg,
                    "recommendation": "Aumenta la longitud y usa variedad de caracteres."
                })
                score_impact += (85 - strength_score)
        else:
            # Análisis específico para PINs
            if len(password) < 4:
                vulnerabilities.append({
                    "type": "weak",
                    "severity": "high",
                    "message": "PIN demasiado corto (menos de 4 dígitos).",
                    "recommendation": "Usa al menos 4 dígitos para tu PIN."
                })
                score_impact += 40
            
            # Detectar secuencias (1234, 4321, etc.)
            if password.isdigit():
                is_seq = password in "01234567890" or password in "09876543210"
                is_rep = len(set(password)) == 1
                
                if is_seq or is_rep:
                    vulnerabilities.append({
                        "type": "pin_pattern",
                        "severity": "high",
                        "message": "PIN con patrón obvio (secuencial o repetido).",
                        "recommendation": "Evita usar combinaciones fáciles de adivinar como '1234' o '0000'."
                    })
                    score_impact += 50

            # Patrones de cumpleaños (YYYY, DDMM) - Heurística simple
            if len(password) == 4 and password.isdigit():
                year = int(password)
                if 1950 <= year <= 2025: # Rango probable de años
                    vulnerabilities.append({
                        "type": "contextual",
                        "severity": "medium",
                        "message": "El PIN parece ser un año. Evita usar fechas de nacimiento.",
                        "recommendation": "No uses años o fechas importantes como PIN."
                    })
                    score_impact += 30
        
        # 2. Análisis Contextual (Fuga de información y patrones)
        lower_pass = password.lower()
        
        # 2a. Información Personal
        if username and len(username) > 3 and username.lower() in lower_pass:
            vulnerabilities.append({
                "type": "contextual",
                "severity": "high",
                "message": "La contraseña contiene tu nombre de usuario.",
                "recommendation": "Evita usar información personal en tus contraseñas."
            })
            score_impact += 35

        if title and len(title) > 3 and title.lower() in lower_pass:
            vulnerabilities.append({
                "type": "contextual",
                "severity": "medium",
                "message": f"La contraseña contiene el nombre del servicio ({title}).",
                "recommendation": "No incluyas el nombre del sitio en la contraseña."
            })
            score_impact += 25

        # 2b. Patrones de Teclado y Palabras Comunes
        keyboard_walks = ["qwerty", "asdfgh", "zxcvbn", "123456", "qazwsx", "plmnko"]
        common_words = ["password", "contraseña", "admin", "bienvenido", "welcome", "google", "facebook", "paisa", "colombia"]
        
        for walk in keyboard_walks:
            if walk in lower_pass:
                vulnerabilities.append({
                    "type": "pattern",
                    "severity": "high",
                    "message": f"Patrón de teclado detectado ('{walk}').",
                    "recommendation": "Evita secuencias de teclas adyacentes."
                })
                score_impact += 30
                break

        for word in common_words:
            if word in lower_pass:
                vulnerabilities.append({
                    "type": "common_word",
                    "severity": "medium",
                    "message": f"Contiene una palabra muy común ('{word}').",
                    "recommendation": "Usa palabras aleatorias o frases de contraseña (passphrases)."
                })
                score_impact += 20
                break

        # 2c. Chequeo de contraseñas filtradas (Top local)
        leaked_top = ["123456", "password", "12345678", "qwerty", "12345", "123456789", "111111"]
        if lower_pass in leaked_top:
            vulnerabilities.append({
                "type": "leaked",
                "severity": "high",
                "message": "Contraseña extremadamente común y filtrada.",
                "recommendation": "Cambia esta contraseña inmediatamente, es la primera en ser probada por atacantes."
            })
            score_impact += 60

        # 2d. Repetición y Entropía visual (e.g. Aa1!Aa1!)
        if len(password) >= 8:
            half = len(password) // 2
            if password[:half] == password[half:] or (len(password) >= 12 and password[:4] == password[4:8] == password[8:12]):
                vulnerabilities.append({
                    "type": "pattern",
                    "severity": "medium",
                    "message": "Estructura repetitiva detectada.",
                    "recommendation": "Evita repetir el mismo bloque de caracteres."
                })
                score_impact += 25

        # 3. Análisis de Antigüedad
        try:
            last_update = datetime.fromisoformat(updated_at)
            days_old = (datetime.now() - last_update).days
            
            # Rotación variable según contexto
            max_days = 180 if category_id in HIGH_RISK_CATEGORIES else 365
            
            if days_old > max_days:
                vulnerabilities.append({
                    "type": "old",
                    "severity": "medium" if category_id in HIGH_RISK_CATEGORIES else "low",
                    "message": f"Contraseña antigua (creada hace {days_old} días).",
                    "recommendation": "Es recomendable actualizar esta contraseña periódicamente."
                })
                score_impact += 15
        except:
            pass

        return {
            "is_healthy": len(vulnerabilities) == 0,
            "vulnerabilities": vulnerabilities,
            "score_impact": min(score_impact, 100)
        }

    @staticmethod
    def vault_wide_audit(all_passwords: list[dict], categories: list[dict], auth_key: bytes) -> dict:
        """
        Analiza todo el vault para detectar reutilización y calcular salud general.
        """
        from security.crypto import decrypt
        
        processed_passwords = []
        password_map = {} # password_str -> list of pw_ids
        user_pass_pairs = {} # (user, pass) -> list of pw_ids
        reused_ids = set()
        stuffing_ids = set()
        
        total_weighted_impact = 0
        total_weight = 0
        
        # Mapeo de riesgo por categoría
        # 1: Banca (Crítico), 3: Trabajo (Alto), 6: Email (Alto), Otros (Medio/Bajo)
        risk_weights = {
            1: 3.0, # Crítico
            3: 2.0, # Alto
            6: 2.0, # Alto
        }

        for pw in all_passwords:
            try:
                raw_pass = decrypt(pw["password"], auth_key)
                raw_user = decrypt(pw["username"], auth_key) if pw.get("username") else ""
            except:
                continue

            # Auditoría individual
            analysis = PasswordAuditEngine.evaluate_health(
                raw_pass, raw_user, pw["title"], pw["category_id"], 
                pw["updated_at"], pw.get("password_rules")
            )
            
            pw_analysis = {
                "id": pw["id"],
                "title": pw["title"],
                "category_id": pw["category_id"],
                "analysis": analysis,
                "password_str": raw_pass,
                "user_str": raw_user
            }
            processed_passwords.append(pw_analysis)
            
            # 1. Detección de Reutilización de Contraseña
            if raw_pass in password_map:
                password_map[raw_pass].append(pw["id"])
                for pid in password_map[raw_pass]:
                    reused_ids.add(pid)
            else:
                password_map[raw_pass] = [pw["id"]]

            # 2. Detección de Credential Stuffing (User + Pass idénticos)
            pair = (raw_user, raw_pass)
            if raw_user and raw_pass:
                if pair in user_pass_pairs:
                    user_pass_pairs[pair].append(pw["id"])
                    for pid in user_pass_pairs[pair]:
                        stuffing_ids.add(pid)
                else:
                    user_pass_pairs[pair] = [pw["id"]]

            # Peso para salud general
            weight = risk_weights.get(pw["category_id"], 1.0)
            total_weighted_impact += (analysis["score_impact"] * weight)
            total_weight += weight

        # Marcar reutilización y stuffing en el análisis
        for pw in processed_passwords:
            weight = risk_weights.get(pw["category_id"], 1.0)
            
            # Credential Stuffing (Más grave que solo reuso de pass)
            if pw["id"] in stuffing_ids and len(user_pass_pairs[(pw["user_str"], pw["password_str"])]) > 1:
                pw["analysis"]["vulnerabilities"].append({
                    "type": "stuffing",
                    "severity": "high",
                    "message": "Riesgo crítico: Combinación de Usuario y Contraseña idéntica en otros sitios.",
                    "recommendation": "Si un sitio es hackeado, atacantes entrarán a todos los demás usando esta misma combinación. ¡Cambia esto primero!"
                })
                pw["analysis"]["is_healthy"] = False
                total_weighted_impact += (40 * weight)
            
            # Reutilización simple
            elif pw["id"] in reused_ids and len(password_map[pw["password_str"]]) > 1:
                pw["analysis"]["vulnerabilities"].append({
                    "type": "reused",
                    "severity": "high",
                    "message": "Contraseña reutilizada en múltiples cuentas.",
                    "recommendation": "Usa una contraseña única para cada servicio."
                })
                pw["analysis"]["is_healthy"] = False
                total_weighted_impact += (25 * weight)

        # Calcular Salud Global (0-100)
        health_score = 100
        if total_weight > 0:
            avg_impact = total_weighted_impact / total_weight
            health_score = max(0, 100 - avg_impact)

        return {
            "overall_score": round(health_score),
            "processed_passwords": processed_passwords,
            "reused_groups": [ids for ids in password_map.values() if len(ids) > 1]
        }
