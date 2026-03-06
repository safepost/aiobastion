# -*- coding: utf-8 -*-
"""
Gestion des sessions HTTP pour aiobastion.

Ce module centralise la création, la maintenance et la fermeture des sessions
aiohttp utilisées par les classes EPV (PVWA) et EPV_AIM (AIM).
Chaque endpoint dispose de sa propre session indépendante.
"""

import asyncio
import logging
import ssl
import os
from typing import Optional

import aiohttp

from .exceptions import CyberarkException, AiobastionException
from .config import Config


logger = logging.getLogger("aiobastion")


class HttpSession:
    """
    Gestionnaire de session HTTP pour un endpoint CyberArk (PVWA ou AIM).

    Chaque instance gère :
      - une session ``aiohttp.ClientSession`` propre à l'endpoint,
      - un sémaphore limitant la concurrence,
      - les paramètres SSL/TLS (ssl_context, timeout).

    Usage typique ::

        session_mgr = HttpSession(max_concurrent_tasks=10, timeout=30)
        session_mgr.setup_ssl(verify=True)

        session = session_mgr.get_session(token="<token>", cookies=None)
        async with session_mgr.semaphore:
            async with session.get(url) as resp:
                ...

        await session_mgr.close()
    """

    def __init__(
        self,
        max_concurrent_tasks: int = Config.CYBERARK_DEFAULT_MAX_CONCURRENT_TASKS,
        timeout: int = Config.CYBERARK_DEFAULT_TIMEOUT,
    ):
        """
        :param max_concurrent_tasks: Nombre maximum de requêtes simultanées.
        :param timeout: Délai d'attente réseau en secondes.
        """
        self.max_concurrent_tasks: int = max_concurrent_tasks
        self.timeout: int = timeout

        # Session aiohttp et sémaphore (initialisés à la demande)
        self._session: Optional[aiohttp.ClientSession] = None
        self._sema: Optional[asyncio.Semaphore] = None

        # Paramètres de requête construits par setup_ssl()
        self.request_params: Optional[dict] = None

    # ------------------------------------------------------------------
    # Configuration SSL
    # ------------------------------------------------------------------

    def setup_ssl(self, verify: Optional[object] = None) -> None:
        """Configure les paramètres SSL/TLS à partir du paramètre *verify*.

        :param verify: ``True`` (CA système), ``False`` (pas de vérification),
                       chemin vers un fichier ou répertoire CA.
        :raises AiobastionException: Si le fichier/répertoire CA est introuvable ou
                                     si le type est invalide.
        """
        if verify is None:
            verify = Config.CYBERARK_DEFAULT_VERIFY

        if not isinstance(verify, (str, bool)):
            raise AiobastionException(
                f"Type invalide pour le paramètre 'verify' : {type(verify)} — valeur : {verify!r}"
            )

        if isinstance(verify, str):
            if not os.path.exists(verify):
                raise AiobastionException(
                    f"Fichier/répertoire CA introuvable : {verify!r} (paramètre 'verify')."
                )
            if os.path.isdir(verify):
                ssl_ctx = ssl.create_default_context(capath=verify)
            else:
                ssl_ctx = ssl.create_default_context(cafile=verify)
        elif verify:  # True
            ssl_ctx = ssl.create_default_context()
        else:  # False
            ssl_ctx = False  # type: ignore[assignment]

        self.request_params = {"timeout": self.timeout, "ssl": ssl_ctx}

    def setup_ssl_with_client_cert(
        self,
        verify: Optional[object],
        cert: str,
        key: Optional[str] = None,
        passphrase: Optional[str] = None,
    ) -> None:
        """Configure SSL/TLS avec un certificat client (utilisé par AIM).

        :param verify: Vérification du serveur (``True``, ``False``, ou chemin CA).
        :param cert: Chemin vers le certificat public client.
        :param key: Chemin vers la clé privée (optionnel).
        :param passphrase: Mot de passe de la clé privée (optionnel).
        :raises AiobastionException: Si les fichiers sont introuvables ou les
                                     paramètres invalides.
        """
        if verify is None:
            verify = Config.CYBERARK_DEFAULT_VERIFY

        if not isinstance(verify, (str, bool)):
            raise AiobastionException(
                f"Type invalide pour le paramètre 'verify' : {type(verify)} — valeur : {verify!r}"
            )

        if not os.path.exists(cert):
            raise AiobastionException(
                f"Certificat public introuvable : {cert!r} (paramètre 'cert' AIM)."
            )
        if key and not os.path.exists(key):
            raise AiobastionException(
                f"Clé privée introuvable : {key!r} (paramètre 'key' AIM)."
            )

        if isinstance(verify, str):
            if not os.path.exists(verify):
                raise AiobastionException(
                    f"Fichier/répertoire CA introuvable : {verify!r} (paramètre 'verify' AIM)."
                )
            if os.path.isdir(verify):
                ssl_ctx = ssl.create_default_context(capath=verify)
            else:
                ssl_ctx = ssl.create_default_context(cafile=verify)
        else:
            ssl_ctx = ssl.create_default_context()
            if not verify:  # False
                ssl_ctx.check_hostname = False

        ssl_ctx.load_cert_chain(cert, keyfile=key, password=passphrase)

        self.request_params = {"timeout": self.timeout, "ssl": ssl_ctx}

    # ------------------------------------------------------------------
    # Propriétés
    # ------------------------------------------------------------------

    @property
    def is_open(self) -> bool:
        """Renvoie ``True`` si une session active est ouverte."""
        return self._session is not None and not self._session.closed

    @property
    def semaphore(self) -> asyncio.Semaphore:
        """Retourne le sémaphore, en le créant si nécessaire."""
        if self._sema is None:
            self._sema = asyncio.Semaphore(self.max_concurrent_tasks)
        return self._sema

    # ------------------------------------------------------------------
    # Gestion de la session
    # ------------------------------------------------------------------

    def get_session(
        self,
        token: Optional[str] = None,
        cookies: Optional[object] = None,
    ) -> aiohttp.ClientSession:
        """Retourne la session active, en la créant si nécessaire.

        La session est construite avec les en-têtes d'authentification adaptés :
        - Sans token : en-tête ``Authorization: None`` (phase de login).
        - Avec token  : en-tête ``Authorization: <token>``.

        :param token: Jeton d'autorisation PVWA (``None`` avant authentification).
        :param cookies: Cookies à injecter dans la nouvelle session (keep_cookies).
        :return: La session ``aiohttp.ClientSession`` en cours.
        """
        content_type = "application/json"

        if self._session is None or self._session.closed:
            if token is None:
                head = {"Content-type": content_type, "Authorization": "None"}
                self._session = aiohttp.ClientSession(headers=head)
                logger.debug("HttpSession: nouvelle session (sans token) : %s", self._session)
            else:
                head = {"Content-type": content_type, "Authorization": token}
                self._session = aiohttp.ClientSession(headers=head, cookies=cookies)
                logger.debug("HttpSession: nouvelle session (avec token) : %s", self._session)

        if self._sema is None:
            self._sema = asyncio.Semaphore(self.max_concurrent_tasks)

        return self._session

    def get_anonymous_session(self) -> aiohttp.ClientSession:
        """Retourne une session sans en-tête d'autorisation (ex. : AIM via certificat).

        Crée la session si elle n'existe pas encore.

        :return: La session ``aiohttp.ClientSession`` en cours.
        """
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
            logger.debug("HttpSession: nouvelle session anonyme : %s", self._session)

        if self._sema is None:
            self._sema = asyncio.Semaphore(self.max_concurrent_tasks)

        return self._session

    async def close(self) -> None:
        """Ferme la session HTTP et réinitialise le sémaphore."""
        logger.debug("HttpSession: fermeture de la session")
        try:
            if self._session and not self._session.closed:
                await self._session.close()
        except (CyberarkException, AttributeError):
            pass
        finally:
            self._session = None
            self._sema = None

    # ------------------------------------------------------------------
    # Context manager (usage autonome)
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "HttpSession":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

