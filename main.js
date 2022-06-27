"use strict";

/*
 * Created with @iobroker/create-adapter v2.1.1
 */

// The adapter-core module gives you access to the core ioBroker functions
// you need to create an adapter
const utils = require("@iobroker/adapter-core");
const axios = require("axios").default;
const qs = require("qs");
const Json2iob = require("./lib/json2iob");
const tough = require("tough-cookie");
const { HttpsCookieAgent } = require("http-cookie-agent/http");

class BoschEbike extends utils.Adapter {
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "bosch-ebike",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        this.on("unload", this.onUnload.bind(this));
        this.deviceArray = [];
        this.tripsArray = [];
        this.json2iob = new Json2iob(this);
        this.cookieJar = new tough.CookieJar();
        this.requestClient = axios.create({
            withCredentials: true,
            httpsAgent: new HttpsCookieAgent({
                cookies: {
                    jar: this.cookieJar,
                },
            }),
        });
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Reset the connection indicator during startup
        this.setState("info.connection", false, true);
        if (this.config.interval < 0.5) {
            this.log.info("Set interval to minimum 0.5");
            this.config.interval = 0.5;
        }
        if (!this.config.username || !this.config.password) {
            this.log.error("Please set username and password in the instance settings");
            return;
        }

        this.updateInterval = null;
        this.reLoginTimeout = null;
        this.refreshTokenTimeout = null;
        this.session = {};
        this.subscribeStates("*");

        if (this.config.type === "connect") {
            this.log.info("Login to eBike Connect");
            await this.login();
            this.session.expires_in = 3600;
            if (this.session.token_value) {
                await this.getDeviceList();
                await this.updateDevices();
                this.updateInterval = setInterval(async () => {
                    await this.updateDevices();
                }, this.config.interval * 60 * 1000);
            }
            this.refreshTokenInterval = setInterval(() => {
                this.refreshToken();
            }, this.session.expires_in * 1000);
        } else {
            this.log.info("Login to eBike flow");
            await this.loginFlow();

            if (this.session.token_value) {
                await this.updateDevicesFlow();
                this.updateInterval = setInterval(async () => {
                    await this.updateDevicesFlow();
                }, this.config.interval * 60 * 1000);
            }
        }
    }
    async login() {
        await this.requestClient({
            method: "post",
            url: "https://www.ebike-connect.com/ebike/api/app/token/public",
            headers: {
                accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                "content-type": "application/json",
                "cache-control": "no-store",
                "protect-from": "CSRF",
                "accept-language": "de-de",
                "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
            },
            data: JSON.stringify({
                mobile_id: "1B50636-3AC4-48B1-A851-63BAD39EAEC6",
                password: this.config.password,
                username: this.config.username,
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.setState("info.connection", true, true);
                this.session = res.data;
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async loginFlow() {
        await this.requestClient({
            method: "get",
            url: "https://p9.authz.bosch.com/auth/realms/obc/protocol/openid-connect/auth?prompt=login&nonce=X7Huv5UrsmpElv62Gf8AOm6f933uwCDTHxUXk-Klmfw&response_type=code&kc_idp_hint=ciam-p&scope=openid%20offline_access&code_challenge=jj-YWlMFPXzAOLtEvyRBPxyr-k4z63KrQ4aOodvu0G4&code_challenge_method=S256&redirect_uri=onebikeapp-ios://com.bosch.ebike.onebikeapp/oauth2redirect&client_id=one-bike-app&state=QxAKjgYO_u6wEw_YwaR3AnV8pVBa9MO0ythfehuifR4",
            headers: {
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "de-de",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
            },
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        const response = await this.requestClient({
            method: "post",
            url: "https://identity-myprofile.bosch.com/ids/login?ReturnUrl=%2Fids%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dcentralids_65EC204B-85B2-4EC3-8BB7-F4B0F69D77D7%26redirect_uri%3Dhttps%253A%252F%252Fidentity.bosch.com%26response_type%3Dcode%26scope%3Dopenid%2520profile%2520email%26state%3DOpenIdConnect.AuthenticationProperties%253DxX2SzcPVyR2nt2Ipe1x0YyovheU2qK89M80DPAMa_ta1Lz-ops_9kgFDOZFZqCclxNF46kuf8KaKEd-OrcuuTEVb6XcprN-pJgdqApWtTDiK3vmQsBEEaycpG2NaRgya6j2W3QO8cpJ1YsMeZgKKGvzoUDKOWi616_-wOToU8A21Fju3cOhXzi9ycm_-UO1tQDtFK3uIQTzv9wQMAH4viYg1OndaSBZ1Rv6egSXTsTQh5AJrGURAvhuQp_SAmxcVqsp2ALSQuk5I3LHzttbJehCL2AM%26nonce%3D637919259193303869.YjBlMTcxMDktYmJlYy00MmJhLWIwZGEtZjcyNGJhZjJjNzY2YTc4MDJiMTYtZTY0YS00MWRlLTk0ZTEtMzZlNTIzNWE2OWNm%26code_challenge%3Dx1DLOjEgH3LR0BMfoQ8DNJtpdTDGDZXkCUb7SHP8dJE%26code_challenge_method%3DS256%26postConfirmReturnUrl%3Dhttps%253A%252F%252Fidentity.bosch.com%252Fconnect%252Fauthorize%253Fscope%253Dopenid%252520email%252520profile%252520offline_access%2526state%253DnNJW4E9DTUBlsntqcb_zx0D-SJl-jGJb_Ikf6ZdLQ5c.uIg-OG3ihdM.one-bike-app%2526response_type%253Dcode%2526client_id%253Dciamids_24CC41EE-35D8-49FB-84C3-4B2FDCE51C9D%2526redirect_uri%253Dhttps%25253A%25252F%25252Fp9.authz.bosch.com%25252Fauth%25252Frealms%25252Fobc%25252Fbroker%25252Fciam-p%25252Fendpoint%2526nonce%253DGo4s0vFA4pIr5if_0fooYw%26x-client-SKU%3DID_NET461%26x-client-ver%3D6.7.1.0",
            headers: {
                Host: "identity-myprofile.bosch.com",
                Origin: "null",
                Cookie: ".AspNetCore.Antiforgery.YON2cgwh6ro=CfDJ8CQ7BaU1RwBJjNvLLUxydOE-fUq4HGhBIEOFy722f-7X8ed_2KNg7CJM_nA2F4hDwNVEljA3HNkzUH-xUIAek4uykT2a9mfa9lNRoOz0sF5jnuHc096j4qnTWJnx2PEFwu3b5J1Csqlk_JsY5bqacO0",
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: qs.stringify({
                "meta-information": "",
                uEmail: this.config.username,
                uPassword: this.config.password,
                ReturnUrl:
                    "/ids/connect/authorize/callback?client_id=centralids_65EC204B-85B2-4EC3-8BB7-F4B0F69D77D7&redirect_uri=https%3A%2F%2Fidentity.bosch.com&response_type=code&scope=openid%20profile%20email&state=OpenIdConnect.AuthenticationProperties%3DxX2SzcPVyR2nt2Ipe1x0YyovheU2qK89M80DPAMa_ta1Lz-ops_9kgFDOZFZqCclxNF46kuf8KaKEd-OrcuuTEVb6XcprN-pJgdqApWtTDiK3vmQsBEEaycpG2NaRgya6j2W3QO8cpJ1YsMeZgKKGvzoUDKOWi616_-wOToU8A21Fju3cOhXzi9ycm_-UO1tQDtFK3uIQTzv9wQMAH4viYg1OndaSBZ1Rv6egSXTsTQh5AJrGURAvhuQp_SAmxcVqsp2ALSQuk5I3LHzttbJehCL2AM&nonce=637919259193303869.YjBlMTcxMDktYmJlYy00MmJhLWIwZGEtZjcyNGJhZjJjNzY2YTc4MDJiMTYtZTY0YS00MWRlLTk0ZTEtMzZlNTIzNWE2OWNm&code_challenge=x1DLOjEgH3LR0BMfoQ8DNJtpdTDGDZXkCUb7SHP8dJE&code_challenge_method=S256&postConfirmReturnUrl=https%3A%2F%2Fidentity.bosch.com%2Fconnect%2Fauthorize%3Fscope%3Dopenid%2520email%2520profile%2520offline_access%26state%3DnNJW4E9DTUBlsntqcb_zx0D-SJl-jGJb_Ikf6ZdLQ5c.uIg-OG3ihdM.one-bike-app%26response_type%3Dcode%26client_id%3Dciamids_24CC41EE-35D8-49FB-84C3-4B2FDCE51C9D%26redirect_uri%3Dhttps%253A%252F%252Fp9.authz.bosch.com%252Fauth%252Frealms%252Fobc%252Fbroker%252Fciam-p%252Fendpoint%26nonce%3DGo4s0vFA4pIr5if_0fooYw&x-client-SKU=ID_NET461&x-client-ver=6.7.1.0",
                __RequestVerificationToken:
                    "CfDJ8CQ7BaU1RwBJjNvLLUxydOHiOgZwVNsCl56VxIUvvSn2TnKoWhRmIJbDuNtgfR-QgOGquLvfEP42EmBxsyy5zSJYEThEcTIFpxwfk1kuGmrnoo5QSwZQA4QVBRLutZjdSQR4B1jS2i4AprP3nLZulU8",
                cbCheckedNoValidationName: "val1a",
            }),
        })
            .then((res) => {
                this.log.error(JSON.stringify(res.data));
            })
            .catch((error) => {
                if (error && error.message.includes("Unsupported protocol")) {
                    return qs.parse(error.request._options.path.split("?")[1]);
                }
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        await this.requestClient({
            method: "post",
            url: "https://p9.authz.bosch.com/auth/realms/obc/protocol/openid-connect/token",
            headers: {
                Host: "p9.authz.bosch.com",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                Accept: "*/*",
                "User-Agent": "Flow/56 CFNetwork/1240.0.4 Darwin/20.6.0",
                "Accept-Language": "de-de",
            },
            data:
                "code=" +
                response.code +
                "&code_verifier=kiR_O850zl5hjw_JIn1tjE4zbRZ7t5QwrmADUrvHaHk&redirect_uri=onebikeapp-ios://com.bosch.ebike.onebikeapp/oauth2redirect&client_id=one-bike-app&grant_type=authorization_code",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.log.debug("Login successful");
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async getDeviceList() {
        await this.requestClient({
            method: "get",
            url: "https://www.ebike-connect.com/ebike/api/app/devices/my_ebikes",
            headers: {
                accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                "accept-language": "de-de",
                "cache-control": "no-store",
                "protect-from": "CSRF",
                "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
                "x-authorization": +this.session.token_value,
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));

                for (const device of res.data.my_ebikes) {
                    const id = device.id;

                    this.deviceArray.push(id);
                    const name = device.name;

                    await this.setObjectNotExistsAsync(id, {
                        type: "device",
                        common: {
                            name: name,
                        },
                        native: {},
                    });
                    await this.setObjectNotExistsAsync(id + ".remote", {
                        type: "channel",
                        common: {
                            name: "Remote Controls",
                        },
                        native: {},
                    });

                    const remoteArray = [{ command: "Refresh", name: "True = Refresh" }];
                    remoteArray.forEach((remote) => {
                        this.setObjectNotExists(id + ".remote." + remote.command, {
                            type: "state",
                            common: {
                                name: remote.name || "",
                                type: remote.type || "boolean",
                                role: remote.role || "boolean",
                                def: remote.def || false,
                                write: true,
                                read: true,
                            },
                            native: {},
                        });
                    });
                    this.json2iob.parse(id, device);
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    async updateDevices() {
        const statusArray = [
            {
                path: "trips",
                url: "https://www.ebike-connect.com/ebike/api/app/activities/trip/headers?max=20&offset=" + Date.now(),
                desc: "Trips",
            },
            {
                path: "routes",
                url: "https://www.ebike-connect.com/ebike/api/app/navigation/my_items/routes?timestamp=0",
                desc: "Routes",
            },
            {
                path: "destinations",
                url: "https://www.ebike-connect.com/ebike/api/app/navigation/my_items/destinations?timestamp=0",
                desc: "Destinations",
            },
        ];

        for (const id of this.deviceArray) {
            for (const element of statusArray) {
                const url = element.url.replace("$id", id);

                await this.requestClient({
                    method: element.method || "get",
                    url: element.url,
                    headers: {
                        accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                        "accept-language": "de-de",
                        "cache-control": "no-store",
                        "protect-from": "CSRF",
                        "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
                        "x-authorization": +this.session.token_value,
                    },
                })
                    .then(async (res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data) {
                            return;
                        }
                        const data = res.data;

                        const forceIndex = true;
                        const preferedArrayName = null;

                        this.json2iob.parse(id + "." + element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                        await this.setObjectNotExistsAsync(id + "." + element.path + ".json", {
                            type: "state",
                            common: {
                                name: "Raw JSON",
                                write: false,
                                read: true,
                                type: "string",
                                role: "json",
                            },
                            native: {},
                        });
                        this.setState(id + "." + element.path + ".json", JSON.stringify(data), true);
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));
                                this.log.info(element.path + " receive 401 error. Refresh Token in 60 seconds");
                                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                                this.refreshTokenTimeout = setTimeout(() => {
                                    this.refreshToken();
                                }, 1000 * 60);

                                return;
                            }
                        }
                        this.log.error(url);
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            }
        }
    }
    async updateDevicesFlow() {
        await this.refreshToken();
        const trips = await this.requestClient({
            method: "get",
            url: "https://obc-rider-activity.prod.connected-biking.cloud/v1/activity?page=0&size=20&sort=-startTime",
            headers: {
                Host: "obc-rider-activity.prod.connected-biking.cloud",
                accept: "*/*",
                "content-type": "application/json",
                authorization: "Bearer " + this.session.access_token,
                "accept-language": "de-de",
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                if (res.data && res.data.data) {
                    await this.json2iob.parse("trips", res.data.data, { forceIndex: true, preferedArrayName: null, channelName: "Trips" });
                    return res.data.data;
                }
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });

        for (const trip of trips) {
            const id = trip.id;
            if (!this.tripsArray.includes(id)) {
                await this.requestClient({
                    method: "get",
                    url: "https://obc-rider-activity.prod.connected-biking.cloud/v1/activity/" + id + "/detail",
                    headers: {
                        Host: "obc-rider-activity.prod.connected-biking.cloud",
                        accept: "*/*",
                        "content-type": "application/json",
                        authorization: "Bearer " + this.session.access_token,
                        "accept-language": "de-de",
                    },
                })
                    .then(async (res) => {
                        this.log.debug(JSON.stringify(res.data));
                        if (!res.data || !res.data.data) {
                            return;
                        }
                        const data = res.data.data;

                        const forceIndex = true;
                        const preferedArrayName = null;

                        this.json2iob.parse(id + ".detail", data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    })
                    .catch((error) => {
                        if (error.response) {
                            if (error.response.status === 401) {
                                error.response && this.log.debug(JSON.stringify(error.response.data));

                                this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
                                this.refreshTokenTimeout = setTimeout(() => {
                                    this.refreshToken();
                                }, 1000 * 60);

                                return;
                            }
                        }
                        this.log.error(error);
                        error.response && this.log.error(JSON.stringify(error.response.data));
                    });
            }
        }
    }
    async refreshToken() {
        if (this.config.type === "connect") {
            await this.login();
            return;
        }
        await this.requestClient({
            method: "post",
            url: "https://p9.authz.bosch.com/auth/realms/obc/protocol/openid-connect/token",
            headers: {
                Host: "p9.authz.bosch.com",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                Accept: "*/*",
                "User-Agent": "Flow/56 CFNetwork/1240.0.4 Darwin/20.6.0",
                "Accept-Language": "de-de",
            },
            data: qs.stringify({
                refresh_token: this.session.refresh_token,
                client_id: "one-bike-app",
                grant_type: "refresh_token",
            }),
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.log.debug("Refresh successful");
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.setState("info.connection", false, true);
            this.refreshTimeout && clearTimeout(this.refreshTimeout);
            this.reLoginTimeout && clearTimeout(this.reLoginTimeout);
            this.refreshTokenTimeout && clearTimeout(this.refreshTokenTimeout);
            this.updateInterval && clearInterval(this.updateInterval);
            this.refreshTokenInterval && clearInterval(this.refreshTokenInterval);
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    async onStateChange(id, state) {
        if (state) {
            if (!state.ack) {
                const deviceId = id.split(".")[2];
                const command = id.split(".")[4];
                if (id.split(".")[3] !== "remote") {
                    return;
                }

                if (command === "Refresh") {
                    this.updateDevices();
                    return;
                }
            }
        }
    }
}

if (require.main !== module) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new BoschEbike(options);
} else {
    // otherwise start the instance directly
    new BoschEbike();
}
