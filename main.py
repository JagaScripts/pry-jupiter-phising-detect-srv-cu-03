import requests
import logging
import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import redis

app = FastAPI(title="Reputation Service", version="1.0.0")
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

# Conexión a Redis
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
CACHE_TTL = int(os.getenv("CACHE_TTL", "3600"))  # 1 hora por defecto

try:
    redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)
    redis_client.ping()
    logger.info("Conexión a Redis establecida")
except Exception as e:
    logger.warning(f"No se pudo conectar a Redis: {e}. Cache deshabilitado.")
    redis_client = None


class ReputacionResponse(BaseModel):
    fuentes: list[dict]


def get_from_cache(key: str):
    """Obtiene datos del cache Redis"""
    if redis_client is None:
        return None
    try:
        cached = redis_client.get(key)
        if cached:
            logger.info(f"Cache hit para {key}")
            return json.loads(cached)
    except Exception as e:
        logger.warning(f"Error leyendo cache: {e}")
    return None


def set_to_cache(key: str, data: list, ttl: int = CACHE_TTL):
    """Guarda datos en el cache Redis"""
    if redis_client is None:
        return
    try:
        redis_client.setex(key, ttl, json.dumps(data))
        logger.info(f"Datos cacheados para {key}")
    except Exception as e:
        logger.warning(f"Error escribiendo cache: {e}")


@app.get("/health")
def health():
    redis_status = "connected" if redis_client else "disconnected"
    return {"status": "healthy", "service": "reputation-service", "redis": redis_status}


@app.get("/reputation/{dominio}", response_model=ReputacionResponse)
def obtener_reputacion(dominio: str):
    """Obtiene reputación de VirusTotal y Urlscan con cache"""
    
    # Intentar obtener del cache
    cache_key = f"reputation:{dominio}"
    cached_data = get_from_cache(cache_key)
    if cached_data:
        return ReputacionResponse(fuentes=cached_data)

    fuentes = []
    timeout = int(os.getenv("API_TIMEOUT", "6"))

    # VirusTotal
    api_key_vt = os.getenv("API_KEY_VT")
    if api_key_vt:
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{dominio}"
            headers = {"accept": "application/json", "x-apikey": api_key_vt}
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            datos = response.json()
            
            if "malicious" in datos.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}):
                score = datos["data"]["attributes"]["last_analysis_stats"]["malicious"]
                fuentes.append({"virustotal": score})
                logger.info(f"VirusTotal score para {dominio}: {score}")
            else:
                fuentes.append({"virustotal": 0})
        except Exception as e:
            logger.warning(f"Error consultando VirusTotal para {dominio}: {e}")
            fuentes.append({"virustotal": 0})
    else:
        logger.warning("API_KEY_VT no configurada")
        fuentes.append({"virustotal": 0})

    # Urlscan
    api_key_urlscan = os.getenv("API_URLSCAN")
    if api_key_urlscan:
        try:
            url = f"https://urlscan.io/api/v1/search/?q=page.domain:{dominio}"
            headers = {"API-Key": api_key_urlscan, "Content-Type": "application/json"}
            response = requests.get(url, headers=headers, timeout=timeout)
            response.raise_for_status()
            datos = response.json()
            
            resultados = datos.get("results", [])
            if resultados:
                uuid = resultados[0]["task"]["uuid"]
                url_result = f"https://urlscan.io/api/v1/result/{uuid}"
                response_result = requests.get(url_result, headers=headers, timeout=timeout)
                response_result.raise_for_status()
                datos_result = response_result.json()
                
                if "malicious" in datos_result.get("stats", {}):
                    score = datos_result["stats"]["malicious"]
                    fuentes.append({"urlscan": score})
                    logger.info(f"Urlscan score para {dominio}: {score}")
                else:
                    fuentes.append({"urlscan": 0})
            else:
                fuentes.append({"urlscan": 0})
        except Exception as e:
            logger.warning(f"Error consultando Urlscan para {dominio}: {e}")
            fuentes.append({"urlscan": 0})
    else:
        logger.warning("API_URLSCAN no configurada")
        fuentes.append({"urlscan": 0})

    # Guardar en cache
    set_to_cache(cache_key, fuentes)

    return ReputacionResponse(fuentes=fuentes)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
