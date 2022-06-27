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
        this.trips = {};
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
        this.config.interval = 0.5;
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
            if (this.session.token_value + ":" + this.session.mobile_id) {
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

            if (this.session.access_token) {
                await this.updateDevicesFlow(true);
                this.updateInterval = setInterval(async () => {
                    await this.updateDevicesFlow();
                }, this.config.interval * 60 * 1000);
            }
        }
    }
    async login() {
        await this.requestClient({
            method: "post",
            url: "https://www.ebike-connect.com/ebikeconnect/api/app/token/public",
            headers: {
                accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                "content-type": "application/json",
                "cache-control": "no-store",
                "protect-from": "CSRF",
                "accept-language": "de-de",
                "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
            },
            data: JSON.stringify({
                mobile_id: "C5A16D86-3AC4-48B1-A851-63BAD39EAEC5",
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
        let loginUrl = "";
        const formData = await this.requestClient({
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
                loginUrl = res.request.path;
                return this.extractHidden(res.data);
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
        if (!formData) {
            this.log.error("Could not extract form data");
            return;
        }
        formData.uEmail = this.config.username;
        formData.uPassword = this.config.password;
        formData["__RequestVerificationToken"] = formData["undefined"];
        delete formData["undefined"];
        delete formData["cbCheckedNoValidationName"];
        formData["meta-information"] = "";
        formData["ReturnUrl"] = formData["ReturnUrl"].replaceAll("&amp;", "&");
        const response = await this.requestClient({
            method: "post",
            url: "https://identity-myprofile.bosch.com" + loginUrl,
            headers: {
                Host: "identity-myprofile.bosch.com",
                Origin: null,
                Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 14_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
                "Accept-Language": "de-de",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data: qs.stringify(formData),
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
        if (!response) {
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
            data:
                "code=" +
                response.code +
                "&code_verifier=kiR_O850zl5hjw_JIn1tjE4zbRZ7t5QwrmADUrvHaHk&redirect_uri=onebikeapp-ios://com.bosch.ebike.onebikeapp/oauth2redirect&client_id=one-bike-app&grant_type=authorization_code",
        })
            .then((res) => {
                this.log.debug(JSON.stringify(res.data));
                this.session = res.data;
                this.log.info("Login successful");
                this.setState("info.connection", true, true);
            })
            .catch((error) => {
                this.log.error(error);
                error.response && this.log.error(JSON.stringify(error.response.data));
            });
    }
    extractHidden(body) {
        const returnObject = {};
        const matches = body.matchAll(/<input (?=[^>]* name=["']([^'"]*)|)(?=[^>]* value=["']([^'"]*)|)/g);
        for (const match of matches) {
            returnObject[match[1]] = match[2];
        }
        return returnObject;
    }
    async getDeviceList() {
        await this.requestClient({
            method: "get",
            url: "https://www.ebike-connect.com/ebikeconnect/api/app/devices/my_ebikes",
            headers: {
                accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                "accept-language": "de-de",
                "cache-control": "no-store",
                "protect-from": "CSRF",
                "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
                "x-authorization": this.session.token_value + ":" + this.session.mobile_id,
            },
        })
            .then(async (res) => {
                this.log.debug(JSON.stringify(res.data));
                this.log.info(`Found ${res.data.length} devices`);
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
                url: "https://www.ebike-connect.com/ebikeconnect/api/app/activities/trip/headers?max=20&offset=" + Date.now(),
                desc: "Trips",
            },
            {
                path: "routes",
                url: "https://www.ebike-connect.com/ebikeconnect/api/app/navigation/my_items/routes?timestamp=0",
                desc: "Routes",
            },
            {
                path: "destinations",
                url: "https://www.ebike-connect.com/ebikeconnect/api/app/navigation/my_items/destinations?timestamp=0",
                desc: "Destinations",
            },
        ];

        for (const element of statusArray) {
            // const url = element.url.replace("$id", id);

            await this.requestClient({
                method: element.method || "get",
                url: element.url,
                headers: {
                    accept: "application/vnd.ebike-connect.com.v4+json, application/json",
                    "accept-language": "de-de",
                    "cache-control": "no-store",
                    "protect-from": "CSRF",
                    "user-agent": "oea_ios/4.8.1 (iPhone; iOS 14.8; Scale/3.00)",
                    "x-authorization": this.session.token_value + ":" + this.session.mobile_id,
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

                    this.json2iob.parse(element.path, data, { forceIndex: forceIndex, preferedArrayName: preferedArrayName, channelName: element.desc });
                    await this.setObjectNotExistsAsync(element.path + ".json", {
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
                    this.setState(element.path + ".json", JSON.stringify(data), true);
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
                    this.log.error(element.url);
                    this.log.error(error);
                    error.response && this.log.error(JSON.stringify(error.response.data));
                });
        }
    }
    async updateDevicesFlow(noRefresh) {
        if (!noRefresh) {
            await this.refreshToken();
        }

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
        this.log.debug(`Found ${trips.length} trips`);
        for (const trip of trips) {
            const id = trip.id;

            let index = trips.indexOf(trip) + 1;
            if (index < 10) {
                index = "0" + index;
            }
            let details = "";
            if (Object.keys(this.trips).includes(id)) {
                details = this.trips[id];
            } else {
                details = await this.requestClient({
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
                        this.trips[id] = res.data.data.attributes;
                        return res.data.data.attributes;
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
            await this.setObjectNotExistsAsync("trips." + index + ".details", {
                type: "state",
                common: {
                    name: "Trip Details",
                    write: false,
                    read: true,
                    type: "string",
                    role: "json",
                },
                native: {},
            });
            await this.setStateAsync("trips." + index + ".details", JSON.stringify(details), true);
        }
    }
    async refreshToken() {
        this.log.debug("Refresh token");
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
