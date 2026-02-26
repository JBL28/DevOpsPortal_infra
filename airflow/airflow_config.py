#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.
#
"""Airflow webserver config - Keycloak OAuth (version-compatible)"""

import logging
import os

import requests
from flask_appbuilder.security.manager import AUTH_OAUTH

# Airflow 버전별 SecurityManager import 호환 처리
BaseSecurityManager = None

try:
    # 신버전(Provider-FAB 분리형)
    from airflow.providers.fab.auth_manager.security_manager.override import (
        FabAirflowSecurityManagerOverride as BaseSecurityManager,
    )
except Exception:
    try:
        # Airflow 2.x 계열에서 자주 쓰는 경로
        from airflow.www.security import AirflowSecurityManager as BaseSecurityManager
    except Exception:
        # 일부 구버전/환경 fallback
        from airflow.www.fab_security.manager import AirflowSecurityManager as BaseSecurityManager

log = logging.getLogger(__name__)

# Flask-WTF flag for CSRF
WTF_CSRF_ENABLED = True

# ----------------------------------------------------
# AUTHENTICATION CONFIG
# ----------------------------------------------------
AUTH_TYPE = AUTH_OAUTH

AUTH_USER_REGISTRATION = True
# 우선 로그인 성공 확인용으로 기본 역할 부여
AUTH_USER_REGISTRATION_ROLE = "Admin"

# roles 동기화는 일단 끄고(로그인 먼저 성공시키자)
# 나중에 Keycloak roles 매핑 붙일 때 켜도 됨
AUTH_ROLES_SYNC_AT_LOGIN = False

OIDC_ISSUER = "http://host.docker.internal:8090/auth/realms/ROODEV"

OAUTH_PROVIDERS = [
    {
        "name": "keycloak",
        "icon": "fa-key",
        "token_key": "access_token",
        "remote_app": {
            "client_id": "airflow",
            "client_secret": os.environ.get("AIRFLOW_OAUTH_CLIENT_SECRET", ""),
            "api_base_url": f"{OIDC_ISSUER}/protocol/openid-connect/",
            "access_token_url": f"{OIDC_ISSUER}/protocol/openid-connect/token",
            "authorize_url": f"{OIDC_ISSUER}/protocol/openid-connect/auth",
            "request_token_url": None,
            "client_kwargs": {
                "scope": "openid email profile",
            },
            # 일부 버전에서는 redirect_uri가 자동으로 잡히지만,
            # 필요하면 아래처럼 명시 가능:
            # "redirect_uri": "http://host.docker.internal:8088/oauth-authorized/keycloak",
        },
    }
]


class CustomSecurityManager(BaseSecurityManager):
    """
    Keycloak의 userinfo(claims)를 Airflow/FAB userinfo 형식으로 매핑.
    네 에러: 'OAUTH userinfo does not have username or email {}' 해결용.
    """

    def _build_keycloak_userinfo(self, response):
        try:
            access_token = (response or {}).get("access_token")
            if not access_token:
                log.error("No access_token in OAuth response: %s", response)
                return {}

            # 등록된 oauth remote client 가져오기
            remote = self.appbuilder.sm.oauth_remotes.get("keycloak")
            if remote is None:
                log.error("Keycloak oauth remote not found")
                return {}

            # Keycloak userinfo endpoint 호출
            # api_base_url 이 .../protocol/openid-connect 이므로 상대경로 userinfo 사용
            userinfo_resp = remote.get("userinfo")
            if userinfo_resp is None:
                log.error("userinfo endpoint returned None")
                return {}

            me = userinfo_resp.json() or {}
            log.info("Keycloak userinfo raw: %s", me)

            # 필수값 매핑
            username = (
                me.get("preferred_username")
                or me.get("username")
                or me.get("email")
                or ""
            )
            email = me.get("email") or ""

            # 네 기존 설정에서는 role sync 안 쓰므로 role_keys 없어도 됨
            userinfo = {
                "username": username,
                "email": email,
                "first_name": me.get("given_name", ""),
                "last_name": me.get("family_name", ""),
            }

            # 일부 버전/환경은 name 필드도 참고하므로 추가
            if not userinfo["first_name"] and me.get("name"):
                userinfo["first_name"] = me.get("name")

            if not userinfo["username"] and not userinfo["email"]:
                log.error("Mapped userinfo missing username/email: %s", userinfo)
                return {}

            log.info("Keycloak userinfo mapped for Airflow: %s", userinfo)
            return userinfo

        except Exception as e:
            log.exception("Failed to build Keycloak userinfo: %s", e)
            return {}

    # 신버전/FAB 쪽에서 호출될 수 있는 메서드명
    def get_oauth_user_info(self, provider, response):
        if provider == "keycloak":
            return self._build_keycloak_userinfo(response)
        return {}

    # 구버전/FAB 쪽에서 호출될 수 있는 메서드명
    def oauth_user_info(self, provider, response=None):
        if provider == "keycloak":
            return self._build_keycloak_userinfo(response)
        return {}


SECURITY_MANAGER_CLASS = CustomSecurityManager

# ----------------------------------------------------
# Theme CONFIG
# ----------------------------------------------------
APP_THEME = "readable.css"