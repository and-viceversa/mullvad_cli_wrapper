import warnings
from typing import Literal

import invoke
from invoke import run, UnexpectedExit, Failure, ThreadException, Result


class VersionWarning(Warning):
    """Class for warnings about version mismatches."""

    def __init__(self, *args, **kwargs):
        pass


class MullvadCLIWrapper:
    WRAPPER_VERSION = "2024.5"
    f"""
    Built on mullvad-cli {WRAPPER_VERSION}
    """
    CLI_VERSION = run("mullvad --version", hide="both").stdout.split(" ")[1]
    if WRAPPER_VERSION != CLI_VERSION:
        warnings.warn(
            f"The installed mullvad-cli version is '{CLI_VERSION}'. This wrapper was built for version {WRAPPER_VERSION}. The command line options may have changed.",
            VersionWarning,
        )

    def mullvad_account_create(
        self, hide: bool | str = True, **kwargs
    ) -> invoke.Result:
        """
        Create and log in on a new account
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account create", hide=hide, **kwargs)

    def mullvad_account_login(
        self, account: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Log in on an account
        :param account: The Mullvad account token to configure the client with
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account login", options=account, hide=hide, **kwargs)

    def mullvad_account_logout(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Log out of the current account
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account logout", hide=hide, **kwargs)

    def mullvad_account_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display information about the current account
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account get", hide=hide, **kwargs)

    def mullvad_account_list_devices(
        self, account: str = "", hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        List devices associated with an account
        :param account: Mullvad account number (current account if not specified)
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad account list-devices", options=account, hide=hide, **kwargs
        )

    def mullvad_account_revoke_devices(
        self, device: str = "", hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Revoke a device associated with an account
        :param device: Name or UID of the device to revoke
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad account revoke-device", options=device, hide=hide, **kwargs
        )

    def mullvad_account_redeem(
        self, voucher: str = "", hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Redeem a voucher
        :param voucher: Name or UID of the device to revoke
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account redeem", options=voucher, hide=hide, **kwargs)

    def mullvad_auto_connect_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current auto-connect setting
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad auto-connect get", hide=hide, **kwargs)

    def mullvad_auto_connect_set(
        self, policy: Literal["on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Change auto-connect setting
        :param policy: One of "on" or "off"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad auto-connect set", options=policy, hide=hide, **kwargs)

    def mullvad_beta_program_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Get beta notifications setting
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad beta-program get", hide=hide, **kwargs)

    def mullvad_beta_program_set(
        self, policy: Literal["on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Change beta notifications setting
        :param policy: One of "on" or "off"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad beta-program set", options=policy, hide=hide, **kwargs)

    def mullvad_lockdown_mode_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current lockdown mode setting
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad lockdown-mode get", hide=hide, **kwargs)

    def mullvad_lockdown_mode_set(
        self, policy: Literal["on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Change the lockdown mode setting
        :param policy: One of "on" or "off"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad lockdown-mode set", options=policy, hide=hide, **kwargs
        )

    def mullvad_dns_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current DNS settings
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad lockdown-mode get", hide=hide, **kwargs)

    def mullvad_dns_set_default(
        self,
        options: list[
            Literal[
                "--block-ads",
                "--block-trackers",
                "--block-malware",
                "--block-adult-content",
                "--block-gambling",
                "--block-social-media",
            ]
        ],
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Use a default DNS server, with or without content blocking
        :param options: list[str] Content blocking options. Possible options:
            [
                "--block-ads",
                "--block-trackers",
                "--block-malware",
                "--block-adult-content",
                "--block-gambling",
                "--block-social-media",
            ]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad dns set default", options=" ".join(options), hide=hide, **kwargs
        )

    def mullvad_dns_set_custom(
        self,
        servers: list[str],
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Set a list of custom DNS servers
        :param servers: list[str] One or more IP addresses pointing to DNS resolvers
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad dns set custom", options=" ".join(servers), hide=hide, **kwargs
        )

    def mullvad_lan_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current local network sharing setting
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad lan get", hide=hide, **kwargs)

    def mullvad_lan_set(
        self, policy: Literal["allow", "block"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Change allow LAN setting
        :param policy: One of "allow" or "block"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad lan set", options=policy, hide=hide, **kwargs)

    def mullvad_connect(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Connect to a VPN relay
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad connect", hide=hide, **kwargs)

    def mullvad_disconnect(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Disconnect from the VPN
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad disconnect", hide=hide, **kwargs)

    def mullvad_reconnect(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Reconnect to any matching VPN relay
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad disconnect", hide=hide, **kwargs)

    def mullvad_bridge_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Get current bridge settings
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad bridge get", hide=hide, **kwargs)

    def mullvad_bridge_set_state(
        self, policy: Literal["auto", "on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Specify whether to use a bridge
        :param policy: One of "auto", "on" or "off"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad bridge set state", options=policy, hide=hide, **kwargs)

    def mullvad_bridge_set_location(
        self, location: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Set country or city to select relays from. Use the 'mullvad bridge list' command to show available alternatives
        Select bridge using a country: mullvad bridge set location se
        Select bridge using a country and city: mullvad bridge set location se got
        Select bridge using a country, city and hostname: mullvad bridge set location se got se-got-br-001
        Select bridge using only its hostname: mullvad bridge set location se-got-br-001
        :param location: Any of the following
            <COUNTRY>   A two-letter country code, or 'any'
            [CITY]      A three-letter city code
            [HOSTNAME]  A host name, such as "se-got-wg-101"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set location", options=location, hide=hide, **kwargs
        )

    def mullvad_bridge_set_custom_list(
        self, custom_list_name: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Set custom list to select relays from. Use the 'custom-lists list' command to show available alternatives
        :param custom_list_name: str
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set custom-list",
            options=custom_list_name,
            hide=hide,
            **kwargs,
        )

    def mullvad_bridge_set_provider(
        self, provider: str = "any", hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Set hosting provider(s) to select relays from. The 'list' command shows the available relays and their providers
        :param provider: str Either 'any', or provider to select from
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set provider", options=provider, hide=hide, **kwargs
        )

    def mullvad_bridge_set_ownership(
        self, ownership: Literal["any", "owned", "rented"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Filter relays based on ownership. The 'list' command shows the available relays and whether they're rented
        :param ownership: str Servers to select from: 'any', 'owned', or 'rented'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set ownership", options=ownership, hide=hide, **kwargs
        )

    def mullvad_bridge_set_custom_set_socks5_local(
        self,
        local_port: str,
        remote_ip: str,
        remote_port: str,
        transport_protocol: Literal["TCP", "UDP"] = "TCP",
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Registers a local SOCKS5 proxy. Will allow all local programs to leak traffic *only* to the remote endpoint.
        :param local_port: str The port that the server on localhost is listening on
        :param remote_ip: str The IP of the remote peer
        :param remote_port: str The port of the remote peer
        :param transport_protocol: str The Mullvad App can not know which transport protocol that the remote peer
            accepts, but it needs to know this in order to correctly exempt the connection traffic in the firewall.
            By default, the transport protocol is assumed to be `TCP`, but it can optionally be set to `UDP` as well.
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set custom set socks5 local",
            options=f"{local_port} {remote_ip} {remote_port} --transport-protocol {transport_protocol}",
            hide=hide,
            **kwargs,
        )

    def mullvad_bridge_set_custom_set_socks5_remote(
        self,
        remote_ip: str,
        remote_port: str,
        username: str | None = None,
        password: str | None = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Configure a remote SOCKS5 proxy
        :param remote_ip: str The IP of the remote proxy server
        :param remote_port: str The port of the remote proxy server
        :param username: str Username for authentication against a remote SOCKS5 proxy
        :param password: str Password for authentication against a remote SOCKS5 proxy
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set custom set socks5 remote",
            options=f"{remote_ip} {remote_port} {username if username else ' '} {password if password else ' '}",
            hide=hide,
            **kwargs,
        )

    def mullvad_bridge_set_custom_set_shadowsocks(
        self,
        remote_ip: str,
        remote_port: str,
        password: str,
        cipher: (
            Literal[
                "aes-128-cfb",
                "aes-128-cfb1",
                "aes-128-cfb8",
                "aes-128-cfb128",
                "aes-256-cfb",
                "aes-256-cfb1",
                "aes-256-cfb8",
                "aes-256-cfb128",
                "rc4",
                "rc4-md5",
                "chacha20",
                "salsa20",
                "chacha20-ietf",
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "xchacha20-ietf-poly1305",
                "aes-128-pmac-siv",
                "aes-256-pmac-siv",
            ]
            | None
        ) = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Configure bundled Shadowsocks proxy
        :param remote_ip: str The IP of the remote Shadowsocks-proxy
        :param remote_port: str Port on which the remote Shadowsocks-proxy listens for traffic
        :param password: str Password for authentication
        :param cipher: str Cipher to use [possible values: aes-128-cfb, aes-128-cfb1, aes-128-cfb8, aes-128-cfb128,
        aes-256-cfb, aes-256-cfb1, aes-256-cfb8, aes-256-cfb128, rc4, rc4-md5, chacha20, salsa20, chacha20-ietf,
        aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, aes-128-pmac-siv, aes-256-pmac-siv]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set custom set shadowsocks",
            options=f"{remote_ip} {remote_port} {password} {'--ciper ' + cipher if cipher else ' '}",
            hide=hide,
            **kwargs,
        )

    def mullvad_bridge_set_custom_edit(
        self,
        username: str | None = None,
        password: str | None = None,
        cipher: str | None = None,
        ip: str | None = None,
        port: str | None = None,
        local_port: str | None = None,
        transport_protocol: str | None = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Edit an existing custom bridge configuration
        :param username: str Username for authentication \[Socks5 (Remote proxy)\]
        :param password: str Password for authentication \[Socks5 (Remote proxy), Shadowsocks\]
        :param cipher: str Cipher to use [possible values: aes-128-cfb, aes-128-cfb1, aes-128-cfb8, aes-128-cfb128,
            aes-256-cfb, aes-256-cfb1, aes-256-cfb8, aes-256-cfb128, rc4, rc4-md5, chacha20, salsa20, chacha20-ietf,
            aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, aes-128-pmac-siv, aes-256-pmac-siv]
        :param ip: str The IP of the remote proxy server \[Socks5 (Local & Remote proxy), Shadowsocks\]
        :param port: str The port of the remote proxy server \[Socks5 (Local & Remote proxy), Shadowsocks\]
        :param local_port: str The port that the server on localhost is listening on \[Socks5 (Local proxy)\]
        :param transport_protocol: str The transport protocol used by the remote proxy \[Socks5 (Local proxy)\]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad bridge set custom edit",
            options=f"{'--username ' + username if username else ''} "
            f"{'--password ' + password if password else ''} "
            f"{'--ciper ' + cipher if cipher else ''} "
            f"{'--ip ' + ip if ip else ''} "
            f"{'--port ' + port if port else ''} "
            f"{'--local-port ' + local_port if local_port else ''} "
            f"{'--transport-protocol ' + transport_protocol if transport_protocol else ''}",
            hide=hide,
            **kwargs,
        )

    def mullvad_bridge_set_custom_use(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Use an existing custom bridge configuration
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad bridge set custom use", hide=hide, **kwargs)

    def mullvad_bridge_set_custom_disable(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Stop using the custom bridge configuration
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad bridge set custom disable", hide=hide, **kwargs)

    def mullvad_bridge_list(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        List available bridge relays
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account get", hide=hide, **kwargs)

    def mullvad_relay_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current relay constraints
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad account get", hide=hide, **kwargs)

    def mullvad_relay_set_location(
        self,
        country: str | None,
        city: str | None,
        hostname: str | None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Select a relay using country, city or hostname. The 'mullvad relay list' command shows the available relays and their geographical location
        :param country: str A two-letter country code, or 'any'
        :param city: str A three-letter city code
        :param hostname: str A host name, such as "se-got-wg-101"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        # input checks
        if not any([country, hostname]):
            raise ValueError(
                "mullvad relay set location requires at least a country or hostname"
            )
        if all([country, hostname]):
            raise ValueError(
                "mullvad relay set location does not accept both a country and hostname"
            )
        return self.run(
            f"mullvad relay set location",
            options=f"{country} {city} {hostname}".strip(),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_custom_list(
        self, custom_list: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Set custom list to select relays from. Use the 'custom-lists list' command to show available alternatives
        :param custom_list: str Name of the custom list to use
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set custom-list", options=custom_list, hide=hide, **kwargs
        )

    def mullvad_relay_set_provider(
        self, providers: list[str], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Set hosting provider(s) to select relays from. The 'list' command shows the available relays and their providers
        :param providers: list[str] of providers
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set provider",
            options=" ".join(providers),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_ownership(
        self, ownership: Literal["any", "owned", "rented"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Filter relays based on ownership. The 'list' command shows the available relays and whether they're rented
        :param ownership: str Servers to select from: 'any', 'owned', or 'rented'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set ownership", options=ownership, hide=hide, **kwargs
        )

    def mullvad_relay_set_tunnel_openvpn(
        self,
        port: str,
        transport_protocol: Literal["TCP", "UDP", "any"],
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Set OpenVPN-specific constraints
        :param port: str Port to use, or 'any'
        :param transport_protocol: str Transport protocol to use, or 'any'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set tunnel openvpn",
            options=f"-p {port} -t {transport_protocol}",
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_tunnel_wireguard(
        self,
        port: str,
        ip_version: str,
        use_multihop: Literal["on", "off"],
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Set WireGuard-specific constraints
        :param port: str Port to use, or 'any'
        :param ip_version: str IP protocol to use, or 'any'
        :param use_multihop: str Whether to enable multihop. The location constraints are specified with 'entry-location' [possible values: on, off]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set tunnel wireguard",
            options=f"-p {port} -i {ip_version} -m {use_multihop}",
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_tunnel_protocol(
        self,
        protocol: Literal["any", "wireguard", "openvpn"],
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Set tunnel protocol to use: 'any', 'wireguard', or 'openvpn'
        :param protocol: str One of: 'any', 'wireguard', or 'openvpn'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set tunnel-protocol",
            options=protocol,
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_custom_openvpn(
        self,
        host: str,
        port: str,
        username: str,
        password: str,
        transport_protocol: str = "UDP",
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Use a custom OpenVPN relay
        :param host: str Hostname or IP
        :param port: str Remote port
        :param username: str Username for authentication
        :param password: str Password for authentication
        :param transport_protocol: str Transport protocol to use [default: UDP]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set custom openvpn",
            options=" ".join([host, port, username, password, transport_protocol]),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_set_custom_wireguard(
        self,
        host: str,
        port: str,
        peer_pubkey: str,
        tunnel_ip: list[str],
        v4_gateway: str | None = None,
        v6_gateway: str | None = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Use a custom WireGuard relay
        :param host: str Hostname or IP
        :param port: str Remote port
        :param peer_pubkey: str Base64 encoded public key of remote peer
        :param tunnel_ip: list[str] IP addresses of local tunnel interface
        :param v4_gateway: IPv4 gateway address
        :param v6_gateway: IPv6 gateway address
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad relay set custom wireguard",
            options=" ".join(
                [
                    host,
                    port,
                    peer_pubkey,
                    *tunnel_ip,
                    f"--v4-gateway {v4_gateway}" if v4_gateway else "",
                    f"--v6-gateway {v6_gateway}" if v6_gateway else "",
                ]
            ),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_list(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        List available relays
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad relay list", hide=hide, **kwargs)

    def mullvad_relay_update(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Update the relay list
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad relay update", hide=hide, **kwargs)

    def mullvad_relay_override_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Show current custom fields for servers
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad relay override get", hide=hide, **kwargs)

    def mullvad_relay_override_set_ipv4(
        self, hostname: str, address: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Override entry IPv4 address for a given relay
        :param hostname: str The unique hostname for the server to set the override on
        :param address: str The IPv4 address to use to connect to this server
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad relay override set ipv4",
            options=" ".join([hostname, address]),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_override_set_ipv6(
        self, hostname: str, address: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Override entry IPv6 address for a given relay
        :param hostname: str The unique hostname for the server to set the override on
        :param address: str The IPv6 address to use to connect to this server
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad relay override set ipv6",
            options=" ".join([hostname, address]),
            hide=hide,
            **kwargs,
        )

    def mullvad_relay_override_unset_ipv4(
        self, hostname: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Remove overridden entry IPv4 address for the given server
        :param hostname: str The unique hostname for the server to unset the override on
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad relay override unset ipv4", options=hostname, hide=hide, **kwargs
        )

    def mullvad_relay_override_unset_ipv6(
        self, hostname: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Remove overridden entry IPv6 address for the given server
        :param hostname: str The unique hostname for the server to unset the override on
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad relay override unset ipv6", options=hostname, hide=hide, **kwargs
        )

    def mullvad_relay_override_clear_all(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Unset custom IPs for all servers
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad relay override clear-all", options="-y", hide=hide, **kwargs
        )

    def mullvad_api_access_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the current API access method
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad api-access get", hide=hide, **kwargs)

    def mullvad_api_access_add_socks5_remote(
        self, name: str, remote_ip: str, remote_port: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Configure a remote SOCKS5 proxy
        :param name: str An easy to remember name for this custom proxy
        :param remote_ip: str The IP of the remote proxy server
        :param remote_port: str The port of the remote proxy server
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access add socks5 remote",
            options=" ".join([name, remote_ip, remote_port]),
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_add_socks5_local(
        self,
        name: str,
        local_port: str,
        remote_ip: str,
        remote_port: str,
        disabled: bool = False,
        transport_protocol: Literal["TCP", "UDP"] = "TCP",
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Configure a remote SOCKS5 proxy
        :param name: str An easy to remember name for this custom proxy
        :param local_port: str The port that the server on localhost is listening on
        :param remote_ip: str The IP of the remote peer
        :param remote_port: str The port of the remote peer
        :param disabled: bool Disable the use of this custom access method. It has to be manually enabled at a later stage to be used when accessing the Mullvad API
        :param transport_protocol: str The Mullvad App can not know which transport protocol that the remote peer accepts, but it needs to know this in order to correctly exempt the connection traffic in the firewall.
            By default, the transport protocol is assumed to be `TCP`, but it can optionally be set to `UDP` as well.
            [default: TCP]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access add socks5 local",
            options=" ".join(
                [
                    "-d" if disabled else "",
                    f"--transport-protocol {transport_protocol}",
                    name,
                    local_port,
                    remote_ip,
                    remote_port,
                ]
            ),
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_add_shadowsocks(
        self,
        name: str,
        remote_ip: str,
        remote_port: str,
        password: str,
        disabled: bool = False,
        cipher: (
            Literal[
                "aes-128-cfb",
                "aes-128-cfb1",
                "aes-128-cfb8",
                "aes-128-cfb128",
                "aes-256-cfb",
                "aes-256-cfb1",
                "aes-256-cfb8",
                "aes-256-cfb128",
                "rc4",
                "rc4-md5",
                "chacha20",
                "salsa20",
                "chacha20-ietf",
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "xchacha20-ietf-poly1305",
                "aes-128-pmac-siv",
                "aes-256-pmac-siv",
            ]
            | None
        ) = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Configure a remote SOCKS5 proxy
        :param name: str An easy to remember name for this custom proxy
        :param remote_ip: str The IP of the remote Shadowsocks-proxy
        :param remote_port: str Port on which the remote Shadowsocks-proxy listens for traffic
        :param password: Password for authentication
        :param disabled: bool Disable the use of this custom access method. It has to be manually enabled at a later stage to be used when accessing the Mullvad API
        :param cipher: str Cipher to use [possible values: aes-128-cfb, aes-128-cfb1, aes-128-cfb8, aes-128-cfb128,
            aes-256-cfb, aes-256-cfb1, aes-256-cfb8, aes-256-cfb128, rc4, rc4-md5, chacha20, salsa20, chacha20-ietf,
            aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, aes-128-pmac-siv, aes-256-pmac-siv]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access add shadowsocks",
            options=" ".join(
                [
                    "-d" if disabled else "",
                    f"--cipher {cipher}" if cipher else "",
                    name,
                    remote_ip,
                    remote_port,
                    password,
                ]
            ),
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_list(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Lists all API access methods
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run("mullvad api-access list", hide=hide, **kwargs)

    def mullvad_api_access_edit(
        self,
        index: str,
        name: str,
        username: str,
        password: str,
        ip: str,
        port: str,
        local_port: str,
        transport_protocol: str,
        cipher: (
            Literal[
                "aes-128-cfb",
                "aes-128-cfb1",
                "aes-128-cfb8",
                "aes-128-cfb128",
                "aes-256-cfb",
                "aes-256-cfb1",
                "aes-256-cfb8",
                "aes-256-cfb128",
                "rc4",
                "rc4-md5",
                "chacha20",
                "salsa20",
                "chacha20-ietf",
                "aes-128-gcm",
                "aes-256-gcm",
                "chacha20-ietf-poly1305",
                "xchacha20-ietf-poly1305",
                "aes-128-pmac-siv",
                "aes-256-pmac-siv",
            ]
            | None
        ) = None,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Edit a custom API access method
        :param index: str Which access method to pick
        :param name: str Name of the API access method in the Mullvad client \[All\]
        :param username: str Username for authentication \[Socks5 (Remote proxy)\]
        :param password: str Password for authentication \[Socks5 (Remote proxy), Shadowsocks\]
        :param cipher: str Cipher to use [possible values: aes-128-cfb, aes-128-cfb1, aes-128-cfb8, aes-128-cfb128,
            aes-256-cfb, aes-256-cfb1, aes-256-cfb8, aes-256-cfb128, rc4, rc4-md5, chacha20, salsa20, chacha20-ietf,
            aes-128-gcm, aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305, aes-128-pmac-siv, aes-256-pmac-siv]
        :param ip: str The IP of the remote proxy server \[Socks5 (Local & Remote proxy), Shadowsocks\]
        :param port: str The port of the remote proxy server \[Socks5 (Local & Remote proxy), Shadowsocks\]
        :param local_port: str The port that the server on localhost is listening on \[Socks5 (Local proxy)\]
        :param transport_protocol: The transport protocol used by the remote proxy \[Socks5 (Local proxy)\]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access edit",
            options=" ".join(
                [
                    f"--name {name}",
                    f"--username {username}",
                    f"--password {password}",
                    f"--cipher {cipher}",
                    f"--ip {ip}",
                    f"--port {port}",
                    f"--local-port {local_port}",
                    f"--transport-protocol {transport_protocol}",
                    index,
                ]
            ),
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_remove(
        self, index: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Which access method to pick
        :param index: str Which access method to pick
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access remove",
            options=index,
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_enable(
        self, index: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Enable an API access method
        :param index: str Which access method to pick
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access enable",
            options=index,
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_disable(
        self, index: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Disable an API access method
        :param index: str Which access method to pick
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access disable",
            options=index,
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_use(
        self, index: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Try to use a specific API access method (If the API is unreachable, reverts back to the previous access method)
        Selecting "Direct" will connect to the Mullvad API without going through any proxy. This connection use https and is therefore encrypted.
        Selecting "Mullvad Bridges" respects your current bridge settings
        :param index: str Which access method to pick
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access use",
            options=index,
            hide=hide,
            **kwargs,
        )

    def mullvad_api_access_test(
        self, index: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Try to reach the Mullvad API using a specific access method
        :param index: str Which access method to pick
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad api-access test",
            options=index,
            hide=hide,
            **kwargs,
        )

    def mullvad_obfuscation_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Get current obfuscation settings
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad obfuscation get",
            hide=hide,
            **kwargs,
        )

    def mullvad_obfuscation_set_mode(
        self, mode: Literal["auto", "off", "udp2tcp"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Specifies if obfuscation should be used with WireGuard connections. And if so, what obfuscation protocol it should use
        :param mode: str [possible values: auto, off, udp2tcp]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad obfuscation set mode",
            options=mode,
            hide=hide,
            **kwargs,
        )

    def mullvad_obfuscation_set_udp2tcp(
        self, port: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Specifies the config for the udp2tcp obfuscator
        :param port: str Port to use, or 'any'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad obfuscation set udp2tcp",
            options=f"-p {port}",
            hide=hide,
            **kwargs,
        )

    def mullvad_split_tunnel_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Display the split tunnel status and apps
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad split-tunnel get",
            hide=hide,
            **kwargs,
        )

    def mullvad_split_tunnel_set(
        self, policy: Literal["on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Enable or disable split tunnel
        :param policy: str [possible values: on, off]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad split-tunnel set",
            options=policy,
            hide=hide,
            **kwargs,
        )

    def mullvad_split_tunnel_app_add(
        self, path: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Add an application to the split tunnel
        :param path: str
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad split-tunnel app add",
            options=path,
            hide=hide,
            **kwargs,
        )

    def mullvad_split_tunnel_app_remove(
        self, path: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Remove an application from the split tunnel
        :param path: str
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad split-tunnel app remove",
            options=path,
            hide=hide,
            **kwargs,
        )

    def mullvad_split_tunnel_app_clear(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad split-tunnel app clear",
            hide=hide,
            **kwargs,
        )

    def mullvad_status_listen(
        self,
        verbose: bool = False,
        debug: bool = False,
        json: bool = False,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Listen for tunnel state changes
        :param verbose: Enable verbose output
        :param debug: Enable debug output
        :param json: Format output as JSON
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad status {'-v' if verbose else ''} {'-d' if debug else ''} {'-j' if json else ''} listen",
            hide=hide,
            **kwargs,
        )

    def mullvad_tunnel_get(self, hide: bool = True, **kwargs) -> invoke.Result:
        """
        Show current tunnel options
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            "mullvad tunnel get",
            hide=hide,
            **kwargs,
        )

    def mullvad_tunnel_set_openvpn(
        self, mssfix: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Remove an application from the split tunnel
        :param mssfix: str Configure the mssfix parameter, or 'any'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad tunnel set openvpn",
            options=f"-m {mssfix}",
            hide=hide,
            **kwargs,
        )

    def mullvad_tunnel_set_wireguard_rotate_key(
        self,
        mtu: str,
        quantum_resistant: Literal["auto", "on", "off"],
        daita: Literal["on", "off"],
        rotation_interval: str,
        hide: bool = True,
        **kwargs,
    ) -> invoke.Result:
        """
        Replace the WireGuard key with a new one
        :param mtu: str Configure the tunnel MTU, or 'any'
        :param quantum_resistant: str Configure quantum-resistant key exchange [possible values: auto, on, off]
        :param daita: str Configure whether to enable DAITA [possible values: on, off]
        :param rotation_interval: str The key rotation interval. Number of hours, or 'any'
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad tunnel set wireguard -m {mtu} --quantum-resistant {quantum_resistant} --daita {daita} --rotation-interval {rotation_interval} rotate-key",
            hide=hide,
            **kwargs,
        )

    def mullvad_tunnel_set_ipv6(
        self, state: Literal["on", "off"], hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Enable or disable IPv6 in the tunnel
        :param state: str [possible values: on, off]
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad tunnel set ipv6",
            options=state,
            hide=hide,
            **kwargs,
        )

    def mullvad_version(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Show information about the current Mullvad version and available versions
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad version",
            hide=hide,
            **kwargs,
        )

    def mullvad_factory_reset(
        self, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Reset settings, caches, and logs
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad factory-reset",
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_new(
        self, name: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Create a new custom list
        :param name: str A name for the new custom list
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list new",
            options=name,
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_list(
        self, name: str | None, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Show all custom lists or retrieve a specific custom list
        :param name: str A custom list. If omitted, all custom lists are shown
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list list",
            options=name if name else "",
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_edit_add(
        self, name: str, country: str, city: str | None, hostname: str | None, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Edit a custom list
        :param name: str A custom list
        :param country: str A two-letter country code, or 'any'
        :param city: str A three-letter city code
        :param hostname: str A host name, such as "se-got-wg-101"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list edit add",
            options=" ".join([name, country, city if city else "", hostname if hostname else ""]),
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_edit_remove(
        self, name: str, country: str, city: str | None, hostname: str | None, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Remove a location from some custom list
        :param name: str A custom list
        :param country: str A two-letter country code, or 'any'
        :param city: str A three-letter city code
        :param hostname: str A host name, such as "se-got-wg-101"
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list edit remove",
            options=" ".join([name, country, city if city else "", hostname if hostname else ""]),
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_edit_rename(
        self, name: str, new_name: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Rename a custom list
        :param name: str Current name of the custom list
        :param new_name: str A new name for the custom list
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list edit rename",
            options=f"{name} {new_name}",
            hide=hide,
            **kwargs,
        )

    def mullvad_custom_list_delete(
        self, name: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Delete a custom list
        :param name: str A custom list
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad custom-list delete",
            options=name,
            hide=hide,
            **kwargs,
        )

    def mullvad_import_settings(
        self, file: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Apply a JSON patch generated by 'export-settings'
        :param file: str File to read from. If this is "-", read from standard input
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad import-settings",
            options=file,
            hide=hide,
            **kwargs,
        )

    def mullvad_export_settings(
        self, file: str, hide: bool = True, **kwargs
    ) -> invoke.Result:
        """
        Export a JSON patch based on the current settings
        :param file: str File to write to. If this is "-", write to standard output
        :param hide: One of "stdout" to hide stdout, "stderr" to hide stderr, True to hide both, or False to hide neither
        :param kwargs: kwargs passed to invoke.Context.run()
        :return: invoke.Result
        """
        return self.run(
            f"mullvad export-settings",
            options=file,
            hide=hide,
            **kwargs,
        )

    @classmethod
    def run(
        cls,
        cmd: str,
        options: str = "",
        hide: Literal["stdout", "stderr", "both"] | bool = "both",
        **kwargs,
    ) -> Result | None:
        try:
            result = run(f"{cmd} {options}" if options else cmd, hide=hide, **kwargs)
        except UnexpectedExit:
            pass
        except Failure:
            pass
        except ThreadException:
            pass
        else:
            return result
