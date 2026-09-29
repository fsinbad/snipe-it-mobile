// Lets the app reach self-hosted instances that Android's defaults refuse. Since API 28 an app
// may not send cleartext to any host, and since API 24 it does not trust CAs the user installed,
// so an http:// instance and an https:// one with an internal-CA certificate both fail to connect.
//
// One network security config fixes both. It cannot name address ranges (<domain> takes hostnames
// only), so cleartext is permitted for every host and the login form refuses http:// to anything
// outside the local network instead (addressGroup in helpers/domainShape.js). android:usesCleartextTraffic is deliberately not set: the config takes precedence
// over it on API 24+, and setting both leaves it unclear which one is in effect.
//
// expo-build-properties exposes usesCleartextTraffic but not networkSecurityConfig, hence this plugin.
// https://developer.android.com/privacy-and-security/security-config
const fs = require('fs');
const path = require('path');
const { AndroidConfig, withAndroidManifest, withDangerousMod } = require('expo/config-plugins');

const RESOURCE_NAME = 'network_security_config';

const NETWORK_SECURITY_CONFIG = `<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
</network-security-config>
`;

function withNetworkSecurityConfigFile(config) {
    return withDangerousMod(config, ['android', async (config) => {
        const resourceFolder = await AndroidConfig.Paths.getResourceFolderAsync(config.modRequest.projectRoot);
        const xmlFolder = path.join(resourceFolder, 'xml');
        await fs.promises.mkdir(xmlFolder, { recursive: true });
        await fs.promises.writeFile(path.join(xmlFolder, `${RESOURCE_NAME}.xml`), NETWORK_SECURITY_CONFIG);
        return config;
    }]);
}

function withNetworkSecurityConfigReference(config) {
    return withAndroidManifest(config, (config) => {
        const mainApplication = AndroidConfig.Manifest.getMainApplicationOrThrow(config.modResults);
        mainApplication.$['android:networkSecurityConfig'] = `@xml/${RESOURCE_NAME}`;
        return config;
    });
}

module.exports = function withNetworkSecurityConfig(config) {
    return withNetworkSecurityConfigReference(withNetworkSecurityConfigFile(config));
};
