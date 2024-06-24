import { test, expect, Page, BrowserContext } from '@playwright/test'
import { authenticator } from 'otplib'
import waitPort from 'wait-port'
import * as redis from 'redis'
import { reloadPage, getTWRBuffer } from '../common/utils'

test.describe('peerbook webrtc connection', ()  => {

    const sleep = (ms) => { return new Promise(r => setTimeout(r, ms)) }
    let redisClient: redis.Redis,
        page: Page,
        context: BrowserContext

    test.afterAll(async () => {
        // delete the user and peer from redis
        await redisClient.quit()
        await context.close()
    })
    test.beforeAll(async ({ browser }) => {
        context = await browser.newContext()
        page = await context.newPage()
        page.on('console', (msg) => console.log('console log:', msg.text()))
        page.on('pageerror', (err: Error) => console.trace('PAGEERROR', err))
        await waitPort({host:'peerbook', port:17777})
        await waitPort({host:'revenuecat', port:1080})
        await page.goto('about:blank')
        redisClient = redis.createClient({url: 'redis://valkey'})
        redisClient.on('error', err => console.log('Redis client error', err))
        await redisClient.connect()
        await redisClient.flushAll()
        // await redisClient.set("tempid:$ValidBearer", "1")
    })

    test('connect to peerbook', async () => {

        const fp = await page.evaluate(async () => {
            window.cert = await RTCPeerConnection.generateCertificate({
              name: "ECDSA",
                // @ts-ignore
              namedCurve: "P-256",
              expires: 31536000000
            })
            const fp = window.cert.getFingerprints()[0].value
            // remove the colons and make it upper case
            return fp.replace(/:/g, '').toUpperCase()
        })
        console.log('fp:', fp)
        await redisClient.hSet("u:123456", {email: "j@example.com"})
        await redisClient.hSet(`peer:${fp}`, {
            name: "test",
            kind: "test",
            user: "123456",
            verified: "1",
            fp: fp,
        })
        await redisClient.sAdd("user:123456", fp)
        await page.evaluate(async () => {
            window.welcomeMessages = 0
            let pc = new RTCPeerConnection({ certificates: [window.cert] })
            let state: string
            let dc = pc.createDataChannel('%')
            window.cdc = dc
            var sessionURL = null

            dc.onopen = () => {
                console.log('datachannel open')
            }
            dc.onmessage = m => {
                const d = new TextDecoder("utf-8"),
                      msg = JSON.parse(d.decode(m.data))
                if ("peers" in msg) {
                    window.welcomeMessages++
                    console.log('peers:', msg.peers)
                } else if ("ice_servers" in msg) {
                    window.welcomeMessages++
                    console.log('ice servers:', data.ice_servers)
                }
            }
            pc.oniceconnectionstatechange = () => console.log('iceConnectionState:', pc.iceConnectionState)
            pc.createOffer().then(offer => {
                pc.setLocalDescription(offer)
                fetch(`http://peerbook:17777/offer`, {
                      method: 'post',
                      body: offer.sdp
                 }).then(response => {
                     console.log('response:', response.status)
                    if (response.status == 201) {
                        sessionURL = response.headers['location'] || response.headers['Location']
                        return response.text()
                    } else {
                        console.log(`failed to post offer: ${response.status}`)
                        return null
                    }
                }).then(data => {
                    console.log('set remote description:', data)
                    if (!data)
                        return
                    pc.setRemoteDescription({type: "answer", sdp: data})
                      .catch (e => console.log('failed to set remote description', e))
                }).catch(error => console.log(`FAILED: POST to https://peerbook:17777/offer`, error))
            })
            pc.onconnectionstatechange = () => {
                console.log('signalingState:', pc.connectionState)
            }
        })
        let done = false
        while (!done) {
            done = await page.evaluate(() => window.welcomeMessages == 2)
            sleep(100)
        }
    })
    test("ice_servers request", async () => {
        // set the ice servers
        await redisClient.hSet("iceserver:1", {
            url: "stun:stun.l.google.com:19302",
            active: "1",
            username: "123456",
            credential: "7890",
        })
        await page.evaluate(async () => {
            window.iceServers = null
            window.cdc.onmessage = m => {
                const d = new TextDecoder("utf-8"),
                      msg = JSON.parse(d.decode(m.data))
                if ((msg.type == "ack") &&
                    (msg.args.ref = 123456)) {
                    window.iceServers = msg.args.ref
                    console.log('ice servers:', window.iceServers)
                }
            }
            window.cdc.send(JSON.stringify({type: "ice_servers",
                                            message_id: 123456,
                                            time: Date.now()}))
        })
        let done = false
        while (!done) {
            done = await page.evaluate(() => window.iceServers != null)
            sleep(100)
        }
    })
})

