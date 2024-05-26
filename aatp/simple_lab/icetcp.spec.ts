import { test, expect, Page, BrowserContext } from '@playwright/test'
import { authenticator } from 'otplib'
import waitPort from 'wait-port'
import * as redis from 'redis'
import { reloadPage, getTWRBuffer } from '../common/utils'

test.describe('ice tcp connection', ()  => {

    const sleep = (ms) => { return new Promise(r => setTimeout(r, ms)) }
    let redisClient: redis.Redis,
        page: Page,
        context: BrowserContext

    test.afterAll(async () => {
        // delete the user and peer from redis
        redisClient = redis.createClient({url: 'redis://valkey'})
        redisClient.on('error', err => console.log('Redis client error', err))
        await redisClient.connect()
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
        await redisClient.set("tempid:$ValidBearer", "1")
    })

    test('connect to peerbook', async () => {
        await page.evaluate(() => {
            window.done = false
            let pc = new RTCPeerConnection()
            let state: string
            let dc = pc.createDataChannel('%')
            var sessionURL = null

            dc.onopen = () => {
                console.log('datachannel open')
                window.done = true
            }
            dc.onmessage = event => {
                console.log('got message:', event.data)
            }

            pc.oniceconnectionstatechange = () => console.log('iceConnectionState:', pc.iceConnectionState)

            pc.createOffer().then(offer => {
                pc.setLocalDescription(offer)
                fetch(`http://peerbook:17777/offer`, {
                      method: 'post',
                      headers: {
                        'Content-Type': 'application/sdp',
                        'Authorization': 'Bearer $ValidBearer',
                      },
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
                console.log('signalingState:', state)
            }
        })
        let done = false
        while (!done) {
            done = await page.evaluate(() => window.done)
            sleep(100)
        }
    })
})

