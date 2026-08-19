/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'
import dns from 'node:dns'
import net from 'node:net'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function isPrivateOrLoopbackIP (ip: string): boolean {
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some(isNaN)) return true
    // 127.0.0.0/8
    if (parts[0] === 127) return true
    // 10.0.0.0/8
    if (parts[0] === 10) return true
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true
    // 169.254.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true
    // 0.0.0.0/8
    if (parts[0] === 0) return true
    return false
  } else if (net.isIPv6(ip)) {
    const canonical = ip.toLowerCase().trim()
    // ::1
    if (canonical === '::1' || canonical === '0:0:0:0:0:0:0:1' || canonical === '::0001') return true
    // ::
    if (canonical === '::' || canonical === '0:0:0:0:0:0:0:0') return true
    // fe80::/10
    if (canonical.startsWith('fe80:')) return true
    // fc00::/7
    if (canonical.startsWith('fc') || canonical.startsWith('fd')) return true
    // IPv4-mapped IPv6
    if (canonical.startsWith('::ffff:')) {
      const ipv4Part = ip.substring(7)
      return isPrivateOrLoopbackIP(ipv4Part)
    }
    return false
  }
  return true
}

async function isSafeHost (hostname: string): Promise<boolean> {
  const hostLower = hostname.toLowerCase().trim()
  if (hostLower === 'localhost' || hostLower.endsWith('.local') || hostLower.endsWith('.localhost')) {
    return false
  }

  if (net.isIP(hostLower)) {
    return !isPrivateOrLoopbackIP(hostLower)
  }

  try {
    const addresses = await dns.promises.lookup(hostname, { all: true })
    for (const addr of addresses) {
      if (isPrivateOrLoopbackIP(addr.address)) {
        return false
      }
    }
    return true
  } catch (err) {
    return false
  }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const parsedUrl = new URL(url)
          if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            next(new Error('Only HTTP and HTTPS protocols are allowed'))
            return
          }
          if (parsedUrl.port !== '' && parsedUrl.port !== '80' && parsedUrl.port !== '443') {
            next(new Error('Only standard HTTP/HTTPS ports are allowed'))
            return
          }
          const isSafe = await isSafeHost(parsedUrl.hostname)
          if (!isSafe) {
            next(new Error('Blocked unsafe or internal URL'))
            return
          }
        } catch (err) {
          next(new Error('Invalid URL format'))
          return
        }

        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
