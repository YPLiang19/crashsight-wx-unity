
mergeInto(LibraryManager.library, {
  CS_Load: function () {
    if (globalThis.hasLoadCrashSight) {
      return
    }
    globalThis.hasLoadCrashSight = true

    if (typeof globalThis.wx === 'undefined') {
      return
    }


    /**
     * Add integers, wrapping at 2^32.
     * This uses 16-bit operations internally to work around bugs in interpreters.
     *
     * @param {number} x First integer
     * @param {number} y Second integer
     * @returns {number} Sum
     */
    function safeAdd(x, y) {
      var lsw = (x & 0xffff) + (y & 0xffff)
      var msw = (x >> 16) + (y >> 16) + (lsw >> 16)
      return (msw << 16) | (lsw & 0xffff)
    }

    /**
     * Bitwise rotate a 32-bit number to the left.
     *
     * @param {number} num 32-bit number
     * @param {number} cnt Rotation count
     * @returns {number} Rotated number
     */
    function bitRotateLeft(num, cnt) {
      return (num << cnt) | (num >>> (32 - cnt))
    }

    /**
     * Basic operation the algorithm uses.
     *
     * @param {number} q q
     * @param {number} a a
     * @param {number} b b
     * @param {number} x x
     * @param {number} s s
     * @param {number} t t
     * @returns {number} Result
     */
    function md5cmn(q, a, b, x, s, t) {
      return safeAdd(bitRotateLeft(safeAdd(safeAdd(a, q), safeAdd(x, t)), s), b)
    }
    /**
     * Basic operation the algorithm uses.
     *
     * @param {number} a a
     * @param {number} b b
     * @param {number} c c
     * @param {number} d d
     * @param {number} x x
     * @param {number} s s
     * @param {number} t t
     * @returns {number} Result
     */
    function md5ff(a, b, c, d, x, s, t) {
      return md5cmn((b & c) | (~b & d), a, b, x, s, t)
    }
    /**
     * Basic operation the algorithm uses.
     *
     * @param {number} a a
     * @param {number} b b
     * @param {number} c c
     * @param {number} d d
     * @param {number} x x
     * @param {number} s s
     * @param {number} t t
     * @returns {number} Result
     */
    function md5gg(a, b, c, d, x, s, t) {
      return md5cmn((b & d) | (c & ~d), a, b, x, s, t)
    }
    /**
     * Basic operation the algorithm uses.
     *
     * @param {number} a a
     * @param {number} b b
     * @param {number} c c
     * @param {number} d d
     * @param {number} x x
     * @param {number} s s
     * @param {number} t t
     * @returns {number} Result
     */
    function md5hh(a, b, c, d, x, s, t) {
      return md5cmn(b ^ c ^ d, a, b, x, s, t)
    }
    /**
     * Basic operation the algorithm uses.
     *
     * @param {number} a a
     * @param {number} b b
     * @param {number} c c
     * @param {number} d d
     * @param {number} x x
     * @param {number} s s
     * @param {number} t t
     * @returns {number} Result
     */
    function md5ii(a, b, c, d, x, s, t) {
      return md5cmn(c ^ (b | ~d), a, b, x, s, t)
    }

    /**
     * Calculate the MD5 of an array of little-endian words, and a bit length.
     *
     * @param {Array} x Array of little-endian words
     * @param {number} len Bit length
     * @returns {Array<number>} MD5 Array
     */
    function binlMD5(x, len) {
      /* append padding */
      x[len >> 5] |= 0x80 << len % 32
      x[(((len + 64) >>> 9) << 4) + 14] = len

      var i
      var olda
      var oldb
      var oldc
      var oldd
      var a = 1732584193
      var b = -271733879
      var c = -1732584194
      var d = 271733878

      for (i = 0; i < x.length; i += 16) {
        olda = a
        oldb = b
        oldc = c
        oldd = d

        a = md5ff(a, b, c, d, x[i], 7, -680876936)
        d = md5ff(d, a, b, c, x[i + 1], 12, -389564586)
        c = md5ff(c, d, a, b, x[i + 2], 17, 606105819)
        b = md5ff(b, c, d, a, x[i + 3], 22, -1044525330)
        a = md5ff(a, b, c, d, x[i + 4], 7, -176418897)
        d = md5ff(d, a, b, c, x[i + 5], 12, 1200080426)
        c = md5ff(c, d, a, b, x[i + 6], 17, -1473231341)
        b = md5ff(b, c, d, a, x[i + 7], 22, -45705983)
        a = md5ff(a, b, c, d, x[i + 8], 7, 1770035416)
        d = md5ff(d, a, b, c, x[i + 9], 12, -1958414417)
        c = md5ff(c, d, a, b, x[i + 10], 17, -42063)
        b = md5ff(b, c, d, a, x[i + 11], 22, -1990404162)
        a = md5ff(a, b, c, d, x[i + 12], 7, 1804603682)
        d = md5ff(d, a, b, c, x[i + 13], 12, -40341101)
        c = md5ff(c, d, a, b, x[i + 14], 17, -1502002290)
        b = md5ff(b, c, d, a, x[i + 15], 22, 1236535329)

        a = md5gg(a, b, c, d, x[i + 1], 5, -165796510)
        d = md5gg(d, a, b, c, x[i + 6], 9, -1069501632)
        c = md5gg(c, d, a, b, x[i + 11], 14, 643717713)
        b = md5gg(b, c, d, a, x[i], 20, -373897302)
        a = md5gg(a, b, c, d, x[i + 5], 5, -701558691)
        d = md5gg(d, a, b, c, x[i + 10], 9, 38016083)
        c = md5gg(c, d, a, b, x[i + 15], 14, -660478335)
        b = md5gg(b, c, d, a, x[i + 4], 20, -405537848)
        a = md5gg(a, b, c, d, x[i + 9], 5, 568446438)
        d = md5gg(d, a, b, c, x[i + 14], 9, -1019803690)
        c = md5gg(c, d, a, b, x[i + 3], 14, -187363961)
        b = md5gg(b, c, d, a, x[i + 8], 20, 1163531501)
        a = md5gg(a, b, c, d, x[i + 13], 5, -1444681467)
        d = md5gg(d, a, b, c, x[i + 2], 9, -51403784)
        c = md5gg(c, d, a, b, x[i + 7], 14, 1735328473)
        b = md5gg(b, c, d, a, x[i + 12], 20, -1926607734)

        a = md5hh(a, b, c, d, x[i + 5], 4, -378558)
        d = md5hh(d, a, b, c, x[i + 8], 11, -2022574463)
        c = md5hh(c, d, a, b, x[i + 11], 16, 1839030562)
        b = md5hh(b, c, d, a, x[i + 14], 23, -35309556)
        a = md5hh(a, b, c, d, x[i + 1], 4, -1530992060)
        d = md5hh(d, a, b, c, x[i + 4], 11, 1272893353)
        c = md5hh(c, d, a, b, x[i + 7], 16, -155497632)
        b = md5hh(b, c, d, a, x[i + 10], 23, -1094730640)
        a = md5hh(a, b, c, d, x[i + 13], 4, 681279174)
        d = md5hh(d, a, b, c, x[i], 11, -358537222)
        c = md5hh(c, d, a, b, x[i + 3], 16, -722521979)
        b = md5hh(b, c, d, a, x[i + 6], 23, 76029189)
        a = md5hh(a, b, c, d, x[i + 9], 4, -640364487)
        d = md5hh(d, a, b, c, x[i + 12], 11, -421815835)
        c = md5hh(c, d, a, b, x[i + 15], 16, 530742520)
        b = md5hh(b, c, d, a, x[i + 2], 23, -995338651)

        a = md5ii(a, b, c, d, x[i], 6, -198630844)
        d = md5ii(d, a, b, c, x[i + 7], 10, 1126891415)
        c = md5ii(c, d, a, b, x[i + 14], 15, -1416354905)
        b = md5ii(b, c, d, a, x[i + 5], 21, -57434055)
        a = md5ii(a, b, c, d, x[i + 12], 6, 1700485571)
        d = md5ii(d, a, b, c, x[i + 3], 10, -1894986606)
        c = md5ii(c, d, a, b, x[i + 10], 15, -1051523)
        b = md5ii(b, c, d, a, x[i + 1], 21, -2054922799)
        a = md5ii(a, b, c, d, x[i + 8], 6, 1873313359)
        d = md5ii(d, a, b, c, x[i + 15], 10, -30611744)
        c = md5ii(c, d, a, b, x[i + 6], 15, -1560198380)
        b = md5ii(b, c, d, a, x[i + 13], 21, 1309151649)
        a = md5ii(a, b, c, d, x[i + 4], 6, -145523070)
        d = md5ii(d, a, b, c, x[i + 11], 10, -1120210379)
        c = md5ii(c, d, a, b, x[i + 2], 15, 718787259)
        b = md5ii(b, c, d, a, x[i + 9], 21, -343485551)

        a = safeAdd(a, olda)
        b = safeAdd(b, oldb)
        c = safeAdd(c, oldc)
        d = safeAdd(d, oldd)
      }
      return [a, b, c, d]
    }

    /**
     * Convert an array of little-endian words to a string
     *
     * @param {Array<number>} input MD5 Array
     * @returns {string} MD5 string
     */
    function binl2rstr(input) {
      var i
      var output = ''
      var length32 = input.length * 32
      for (i = 0; i < length32; i += 8) {
        output += String.fromCharCode((input[i >> 5] >>> i % 32) & 0xff)
      }
      return output
    }

    /**
     * Convert a raw string to an array of little-endian words
     * Characters >255 have their high-byte silently ignored.
     *
     * @param {string} input Raw input string
     * @returns {Array<number>} Array of little-endian words
     */
    function rstr2binl(input) {
      var i
      var output = []
      output[(input.length >> 2) - 1] = undefined
      for (i = 0; i < output.length; i += 1) {
        output[i] = 0
      }
      var length8 = input.length * 8
      for (i = 0; i < length8; i += 8) {
        output[i >> 5] |= (input.charCodeAt(i / 8) & 0xff) << i % 32
      }
      return output
    }

    /**
     * Calculate the MD5 of a raw string
     *
     * @param {string} s Input string
     * @returns {string} Raw MD5 string
     */
    function rstrMD5(s) {
      return binl2rstr(binlMD5(rstr2binl(s), s.length * 8))
    }

    /**
     * Calculates the HMAC-MD5 of a key and some data (raw strings)
     *
     * @param {string} key HMAC key
     * @param {string} data Raw input string
     * @returns {string} Raw MD5 string
     */
    function rstrHMACMD5(key, data) {
      var i
      var bkey = rstr2binl(key)
      var ipad = []
      var opad = []
      var hash
      ipad[15] = opad[15] = undefined
      if (bkey.length > 16) {
        bkey = binlMD5(bkey, key.length * 8)
      }
      for (i = 0; i < 16; i += 1) {
        ipad[i] = bkey[i] ^ 0x36363636
        opad[i] = bkey[i] ^ 0x5c5c5c5c
      }
      hash = binlMD5(ipad.concat(rstr2binl(data)), 512 + data.length * 8)
      return binl2rstr(binlMD5(opad.concat(hash), 512 + 128))
    }

    /**
     * Convert a raw string to a hex string
     *
     * @param {string} input Raw input string
     * @returns {string} Hex encoded string
     */
    function rstr2hex(input) {
      var hexTab = '0123456789abcdef'
      var output = ''
      var x
      var i
      for (i = 0; i < input.length; i += 1) {
        x = input.charCodeAt(i)
        output += hexTab.charAt((x >>> 4) & 0x0f) + hexTab.charAt(x & 0x0f)
      }
      return output
    }

    /**
     * Encode a string as UTF-8
     *
     * @param {string} input Input string
     * @returns {string} UTF8 string
     */
    function str2rstrUTF8(input) {
      return unescape(encodeURIComponent(input))
    }

    /**
     * Encodes input string as raw MD5 string
     *
     * @param {string} s Input string
     * @returns {string} Raw MD5 string
     */
    function rawMD5(s) {
      return rstrMD5(str2rstrUTF8(s))
    }
    /**
     * Encodes input string as Hex encoded string
     *
     * @param {string} s Input string
     * @returns {string} Hex encoded string
     */
    function hexMD5(s) {
      return rstr2hex(rawMD5(s))
    }
    /**
     * Calculates the raw HMAC-MD5 for the given key and data
     *
     * @param {string} k HMAC key
     * @param {string} d Input string
     * @returns {string} Raw MD5 string
     */
    function rawHMACMD5(k, d) {
      return rstrHMACMD5(str2rstrUTF8(k), str2rstrUTF8(d))
    }
    /**
     * Calculates the Hex encoded HMAC-MD5 for the given key and data
     *
     * @param {string} k HMAC key
     * @param {string} d Input string
     * @returns {string} Raw MD5 string
     */
    function hexHMACMD5(k, d) {
      return rstr2hex(rawHMACMD5(k, d))
    }




    let md5 = {
      /**
 * Calculates MD5 value for a given string.
 * If a key is provided, calculates the HMAC-MD5 value.
 * Returns a Hex encoded string unless the raw argument is given.
 *
 * @param {string} string Input string
 * @param {string} [key] HMAC key
 * @param {boolean} [raw] Raw output switch
 * @returns {string} MD5 output
 */
      md5(string, key, raw) {
        if (!key) {
          if (!raw) {
            return hexMD5(string)
          }
          return rawMD5(string)
        }
        if (!raw) {
          return hexHMACMD5(key, string)
        }
        return rawHMACMD5(key, string)
      }
    }

    function md5Func(arg) {
        return md5.md5(arg)
    }

    // ========================== MD5 Core Begin===============================


    // ========================== CrashSgiht Core Begin===============================
    const StrategyEnableState = {
      Unknow: 0,
      Enable: 1,
      Disable: 2
    }

    let strategyEnableState = StrategyEnableState.Unknow
    let hasInitCrashSight = false
    let hasRegisterErrorCallback = false
    let hasHookConsoleError = false
    let hasMergeExcepionFile = false
    let serverStrategy = {}


    const platformId = 32
    const sdkVersion = '1.3.0'
    const errorReportCMD = 930
    const connnetReportCDM = 940
    const coldStartup = 1
    const hotStartup = 2
    const localStrategyKey = 'crashsight_local_strategy'

    let appId = ''
    let sessionId = ''
    let userId = ''
    let extKV = {}

    let _deviceId = null
    let appVersion = "0.0.0"
    let wxAppIdentify = "none"
    let reportURL = 'https://minigame.crashsight.qq.com/rqd/pb/sync'

    const generateUUID = function () {
      let uuid = '';
      for (let i = 0; i < 32; i++) {
        const random = Math.random() * 16 | 0;
        if (i === 8 || i === 12 || i === 16 || i === 20) {
          uuid += '-';
        }
        uuid += (i === 12 ? 4 : (i === 16 ? (random & 3 | 8) : random)).toString(16);
      }
      return uuid;
    }

    const getDeviceId = function () {
      if (_deviceId) {
        return _deviceId
      }
      _deviceId = wx.getStorageSync('crashsight_device_id')
      if (_deviceId) {
        return _deviceId
      }
      _deviceId = generateUUID()
      wx.setStorageSync('crashsight_device_id', _deviceId)
      return _deviceId
    }

    const buildRequestJson = async function (obj, cmd) {
      let ret = await wx.getNetworkType()
      let deviceInfo = {}
      try {
        deviceInfo = wx.getDeviceInfo()
      } catch (error) {
        deviceInfo['system'] = 'unknow'
        deviceInfo['model'] = 'unknow'
      }
      let request = {}
      request.cmd = cmd
      request.platformId = platformId
      request.prodId = appId
      request.networkType = ret && ret.networkType ? ret.networkType : 'unknown'

      if (cmd === connnetReportCDM) {
        obj.list[0].startCostTime = typeof globalThis.__crashSight.startCostTime === 'undefined' ? -1 : globalThis.__crashSight.startCostTime
      }

      request.sBuffer = obj
      request.model = deviceInfo['model']
      request.osVer = deviceInfo['system']
      request.uploadTime = new Date().getTime()
      request.sessionId = sessionId
      request.deviceId = getDeviceId()
      request.sdkVer = sdkVersion
      request.version = appVersion
      request.bundleId = wxAppIdentify
      let uniPacket = {
        sServantName: 'RqdServer',
        sFuncName: 'sync',
        request: request
      }
      return uniPacket
    }


    const sendHttp = function (body, cmd, callback) {
      let header = {
        platformId: platformId.toString(),
        prodId: appId,
        cmd: cmd,
        sdkVer: sdkVersion,
        appVer: appVersion,
        model: wx.getDeviceInfo()['model'],
        sdkName: "WXCrashSightSDK",
        redisKeyUuid: getDeviceId(),
        bundleId: wxAppIdentify,
        tls: 1,
        "Content-Type": "application/json",
      }
      console.log("[CrashSight][Debug] request body json: " + JSON.stringify(body))
      wx.request({
        url: reportURL,
        method: 'POST',
        header: header,
        data: body,
        success(res) {
          try {
            console.log("[CrashSight][Debug] response data: " + JSON.stringify(res.data))
          } catch (error) {
            console.log("[CrashSight][Error] " + error)
          }
          if (callback) {
            callback(null, res)
          }
        },
        fail(err) {
          try {
            console.log("[CrashSight][Error] network request faild: " + JSON.stringify(err))
          } catch (error) {
            console.log("[CrashSight][Error] " + error)
          }
          if (callback) {
            callback(err, null)
          }
        }
      })
    }

    let mergeInfo = {}
    const sendErrorMessage = async function (expName, msg, stack) {
      try {
        let exceptionUpload = {}
        exceptionUpload.type = "107"
        exceptionUpload.expName = expName
        exceptionUpload.expMessage = typeof msg === 'object' ? JSON.stringify(msg) : msg
        exceptionUpload.callStack = typeof stack === 'object' ? JSON.stringify(stack) : stack
        if (typeof exceptionUpload.expMessage === 'undefined') {
          exceptionUpload.expMessage = 'null'
        }

        if (typeof exceptionUpload.callStack === 'undefined') {
          exceptionUpload.callStack = 'null'
        }

        let deleteAfterUpload = false
        let saveFileName = null
        let hash = undefined
        if (Number(serverStrategy['MG_KEY_MERGE_IMPROVE'])) {
          hash = md5Func(msg + stack)
          if (mergeInfo[hash]) {
            mergeInfo[hash].count++
            wx.setStorageSync('cs_merge_info', mergeInfo)
            console.log('[CrashSight] [Debug] merge not first hash: ' + hash + ', count: ' + mergeInfo[hash].count)
            return
          } else {
            saveFileName = 'cs_exception_' + new Date().getTime() + '_' + hash
            mergeInfo[hash] = { count: 1 }
            wx.setStorageSync('cs_merge_info', mergeInfo)
            console.log('[CrashSight] [Debug] merge fisrt hash: ' + hash + ', count: ' + mergeInfo[hash].count)
          }
        } else {
          saveFileName = 'cs_none_merge_exception_' + new Date().getTime()
          deleteAfterUpload = true
          console.log('[CrashSight] [Debug] not merge ')
        }

        exceptionUpload.userId = userId
        exceptionUpload.crashTime = new Date().getTime()
        exceptionUpload.expuid = generateUUID()
        exceptionUpload.deviceId = getDeviceId()
        exceptionUpload.valueMap = extKV || {}
        exceptionUpload.sessionId = sessionId

        let exceptionUploadPackage = {
          type: 107,
          deviceId: getDeviceId(),
          list: [exceptionUpload]
        }
        let body = await buildRequestJson(exceptionUploadPackage, errorReportCMD)

        if (saveFileName) {
          console.log('[CrashSight] [Debug] save file: ', saveFileName)
          await fileManager.saveFile(saveFileName, JSON.stringify(body))
        }
        sendHttp(body, errorReportCMD.toString(), async (httpError) => {
          if (!httpError && deleteAfterUpload && saveFileName) {
            await fileManager.removeFile(saveFileName)
            console.log('[CrashSight] [Event] upload not merger error message succeess, delete file:' + saveFileName)
          }
        })
      } catch (error) {
        console.log("[CrashSight][Error] " + error)
      }
    }


    const sendHistoryFile = async function (files) {
      console.log('[CrashSight] [Debug] history files:', files)
      if (!files) {
        return
      }
      for (let i = 0; i < files.length; i++) {
        const fileName = files[i]
        let isExceptionFile = fileName.startsWith('cs_none_merge_exception_')
        let isConnectionFile = fileName.startsWith('cs_connection_')
        if (isExceptionFile || isConnectionFile) {
          let content = await fileManager.readFile(fileName)
          if (content !== undefined) {
            try {
              let uniPacket = JSON.parse(content)
              if (isExceptionFile) {
                uniPacket.request.sBuffer.list[0].valueMap['A29'] = 1
              }
              sendHttp(uniPacket, uniPacket.request.cmd.toString(), async (httpError, res) => {
                if (!httpError) {
                  await fileManager.removeFile(fileName)
                }
              })
            } catch (e) {
              console.log('[CrashSight][Error] sendHistoryErrorMessage JSON parse and merge file:', fileName, ', content: ', content, ', error: ', e)
              await fileManager.removeFile(fileName)
            }
          } else {
            await fileManager.removeFile(fileName)
          }
        }
      }
    }

    const sendConnectInfo = async function (startType) {
      try {
        sessionId = generateUUID()
        let summaryInfo = {}
        summaryInfo.startTime = new Date().getTime()
        summaryInfo.startType = startType
        summaryInfo.userId = userId
        summaryInfo.sessionId = sessionId
        summaryInfo.coldStartup = startType == coldStartup

        let userInfoPackage = {
          type: startType,
          deviceId: getDeviceId(),
          list: [summaryInfo]
        }
        let body = await buildRequestJson(userInfoPackage, connnetReportCDM)
        let connectionFileName = 'cs_connection_' + + new Date().getTime()
        await fileManager.saveFile(connectionFileName, JSON.stringify(body))
        sendHttp(body, connnetReportCDM.toString(), async (httpError, res) => {
          if (httpError) {
            return
          }
          await fileManager.removeFile(connectionFileName)
          try {
            if (res.data) {
              if (res.data.cmd == 510) {
                let buffer = res.data.sBuffer
                try {
                  wx.setStorageSync(localStrategyKey, buffer.enable ? StrategyEnableState.Enable : StrategyEnableState.Disable)
                } catch (error) {
                  console.log("[CrashSight][Error] wx.setStorageSync set local strategy error:" + error)
                }
                if (buffer.enable) {
                  if (hasInitCrashSight) {
                    if (!hasMergeExcepionFile) {
                      if (buffer.valueMap && typeof buffer.valueMap === 'object') {
                        serverStrategy = buffer.valueMap
                      }
                      console.log('[CrashSight][Info] serverStrategy: ', serverStrategy)
                      mergeExcepionFile()
                      hasMergeExcepionFile = true
                    }
                    if (strategyEnableState != StrategyEnableState.Enable) {
                      strategyEnableState = StrategyEnableState.Enable
                      registerErrorCallback()
                      console.log("[CrashSight][Info] CrashSight receve enable from server")
                    }
                  }
                } else {
                  if (strategyEnableState != StrategyEnableState.Disable) {
                    strategyEnableState = StrategyEnableState.Disable
                    unregisterErrorCallback()
                    console.log("[CrashSight][Error] CrashSight receve disable from server")
                  }
                }
              }
            }
          } catch (error) {
            console.log("[CrashSight][Error] " + error)
          }
        })
      } catch (error) {
        console.log("[CrashSight][Error] " + error)
      }
    }

    const jsErrorHandler = function (message, stack) {
      if (strategyEnableState == StrategyEnableState.Enable) {
        if (typeof message === 'object') {
          sendErrorMessage('JavaScript Error (wx.onError)', message.message, message.stack)
        } else {
          sendErrorMessage('JavaScript Error (wx.onError)', message, stack)
        }
      }
    }

    const pageNotFoundHandler = function (result) {
      if (strategyEnableState == StrategyEnableState.Enable) {
        sendErrorMessage('WX Page Not Found Error', JSON.stringify(result), null)
      }
    }
    const unhandledRejectionHandler = function (result) {
      if (strategyEnableState == StrategyEnableState.Enable) {
        let message = 'unkonw'
        let stack = ''
        if (result) {
          if (typeof result.reason === 'string') {
            message = result.reason
          } else if (typeof result.reason === 'object') {
            message = result.reason.message
            stack = result.reason.stack
          }
        }
        sendErrorMessage('Unhandle Rejection Promise Error', message, stack)

      }
    }

    const registerConsoleErrorHanler = function () {
      if (hasHookConsoleError) {
        return
      }

      console.log('[CrashSight][Info] register console.error')
      let oldConsoleError = console.error
      Object.defineProperty(console, 'error', {
        value: function () {
          if (strategyEnableState == StrategyEnableState.Enable) {
            if (arguments[0] && arguments[0].stack) {
              let message = arguments[0].message
              let stack = arguments[0].stack
              sendErrorMessage('JavaScript Error(console.error)', message, stack)
            }
          }
          oldConsoleError.apply(console, arguments);
        },
        writable: true,
        configurable: true
      });
      hasHookConsoleError = true
    }

    let fileManager = {

      init: function () {
        if (this.inited === true) {
          return true
        }
        let fs = wx.getFileSystemManager()
        try {
          fs.accessSync(`${wx.env.USER_DATA_PATH}/CrashSight`)
        } catch (e) {
          try {
            fs.mkdirSync(`${wx.env.USER_DATA_PATH}/CrashSight`)
          } catch (e) {
            console.log('[CrashSight][Error] mkdir faild: ' + e)
            return false
          }
        }
        this.inited == true
        return true
      },

      files: function () {
        if (!this.inited) {
          if (!this.init()) {
            console.log('[CrashSight][Error] get files init fileManager error')
            return []
          }
        }
        let files = []
        try {
          let fs = wx.getFileSystemManager()
          files = fs.readdirSync(`${wx.env.USER_DATA_PATH}/CrashSight`)
        } catch (e) {
          console.log('[CrashSight][Error] readdirSync faild: ' + e)
        }
        return files
      },

      removeFile: function (fileName) {
        if (!this.inited) {
          if (!this.init()) {
            console.log('[CrashSight][Error] removeFile init fileManager error')
            return []
          }
        }
        return new Promise((resolve, reject) => {
          let fs = wx.getFileSystemManager()
          fs.unlink({
            filePath: `${wx.env.USER_DATA_PATH}/CrashSight/${fileName}`,
            success(res) {
              resolve(true)
            },
            fail(err) {
              console.log('[Perfsight] [Error] remove file error: ', err)
              resolve(false)
            }
          })
        })
      },

      saveFile: function (fileName, data) {
        if (!this.inited) {
          if (!this.init()) {
            console.log('[CrashSight][Error] saveFile init fileManager error')
            return []
          }
        }
        return new Promise((resolve, reject) => {
          let fs = wx.getFileSystemManager()
          fs.writeFile({
            filePath: `${wx.env.USER_DATA_PATH}/CrashSight/${fileName}`,
            encoding: 'utf8',
            data: data,
            success() {
              resolve(true)
            },
            fail(err) {
              console.log('[Perfsight] [Error] saveFile init fileManager error: ', err)
              resolve(false)
            }
          })
        })
      },

      readFile: function (fileName) {
        if (!this.inited) {
          if (!this.init()) {
            console.log('[CrashSight][Error] readFile init fileManager error')
            return []
          }
        }
        return new Promise((resolve, reject) => {
          let fs = wx.getFileSystemManager()
          fs.readFile({
            filePath: `${wx.env.USER_DATA_PATH}/CrashSight/${fileName}`,
            encoding: 'utf8',
            success(res) {
              resolve(res.data)
            },
            fail(err) {
              console.log('[Perfsight] [Error] readFile error: ', err)
              resolve(undefined)
            }
          })
        })
      }


    }

    const mergeExcepionFile = async function () {
      let mergeInfo = wx.getStorageSync('cs_merge_info')
      wx.setStorageSync('cs_merge_info', {})
      if (!mergeInfo) {
        mergeInfo = {}
      }
      let files = fileManager.files()
      console.log('[CrashSight] [Debug] mergeInfo:', mergeInfo)
      console.log('[CrashSight] [Debug] merge files:', files)

      if (!files) {
        return
      }
      for (let i = 0; i < files.length; i++) {
        const fileName = files[i]
        if (fileName.startsWith('cs_exception_')) {
          let matchResult = fileName.match(/([a-zA-Z0-9-]+)$/)
          let hash = undefined
          if (matchResult && matchResult.length > 0) {
            hash = matchResult[0]
          } else {
            await fileManager.removeFile(fileName)
            continue
          }

          let info = mergeInfo[hash]
          if (info && info.count > 1) {
            let content = await fileManager.readFile(fileName)
            if (content !== undefined) {
              try {
                let uniPacket = JSON.parse(content)
                uniPacket.request.sBuffer.list[0].crashCount = info.count - 2
                sendHttp(uniPacket, uniPacket.request.cmd.toString(), async (httpError, res) => {
                  if (!httpError) {
                    await fileManager.removeFile(fileName)
                  }
                })
              } catch (e) {
                console.log('[CrashSight][Error] JSON parse and merge file:', fileName, ', content: ', content, ', error: ', e)
                await fileManager.removeFile(fileName)
                continue
              }
            } else {
              continue
            }
          } else {
            await fileManager.removeFile(fileName)
            continue
          }
        }

      }

    }

    const registerErrorCallback = function () {
      if (hasRegisterErrorCallback) {
        console.log('[CrashSight][Warning] repeated call hasRegisterErrorCallback')
        return
      }
      if (wx.onError) {
        console.log('[CrashSight][Info] register wx.onError')
        wx.onError(jsErrorHandler)
      } else {
        console.log('[CrashSight][Warning] no wx.onError function')
      }
      registerConsoleErrorHanler()
      if (wx.onPageNotFound) {
        console.log('[CrashSight][Info] register wx.onPageNotFound')
        wx.onPageNotFound(pageNotFoundHandler)
      } else {
        console.log('[CrashSight][Warning] no wx.onPageNotFound function')
      }
      if (wx.onUnhandledRejection) {
        console.log('[CrashSight][Info] register wx.onUnhandledRejection')
        wx.onUnhandledRejection(unhandledRejectionHandler)
      } else {
        console.log('[CrashSight][Warning] no wx.onUnhandledRejection function')
      }
      hasRegisterErrorCallback = true
    }

    const unregisterErrorCallback = function () {
      if (!hasRegisterErrorCallback) {
        console.log('[CrashSight][Warning] repeated call unregisterErrorCallback')
        return
      }
      if (wx.offError) {
        console.log('[CrashSight][Info] unregister wx.onError')
        wx.offError(jsErrorHandler)
      }
      if (wx.offPageNotFound) {
        console.log('[CrashSight][Info] unregister wx.onPageNotFound')
        wx.offPageNotFound(pageNotFoundHandler)
      }
      if (wx.offUnhandledRejection) {
        console.log('[CrashSight][Info] unregister wx.onUnhandledRejection')
        wx.offUnhandledRejection(unhandledRejectionHandler)
      }
      hasRegisterErrorCallback = false
    }


    let crashSight = {
      start: function (_appId, _reportURL) {
        if (hasInitCrashSight) {
          console.log('[CrashSight][Warning] CrashSight has started')
          return
        }
        if (!_appId) {
          console.log("[CrashSight][Error] appid is null")
          return
        }
        let startBeginTime = new Date().getTime()
        appId = _appId
        if (_reportURL) {
          reportURL = _reportURL
        }
        try {
          strategyEnableState = wx.getStorageSync(localStrategyKey)
          console.log('[CrashSight][Debug] local strategy enable: ' + (strategyEnableState === StrategyEnableState.Enable))
          if (strategyEnableState === undefined || strategyEnableState === null || strategyEnableState === '') {
            strategyEnableState = StrategyEnableState.Enable
          }
        } catch (error) {
          console.log('[CrashSight][Error] wx.getStorageSync get local strategy error:' + error)
          strategyEnableState = StrategyEnableState.Enable
        }
        let historyFiles = []
        if (strategyEnableState != StrategyEnableState.Disable) {
          historyFiles = fileManager.files()
        }
        sendConnectInfo(coldStartup)
        if (strategyEnableState != StrategyEnableState.Disable) {
          registerErrorCallback()
          sendHistoryFile(historyFiles)
        }
        hasInitCrashSight = true
        globalThis.__crashSight.startCostTime = new Date().getTime() - startBeginTime
        console.log('[CrashSight][INFO] CrashSight start success in ', globalThis.__crashSight.startCostTime, 'ms, waiting for enable form server...')
      },

      stop: function () {
        if (!hasInitCrashSight) {
          console.log('[CrashSight][Error] CrashSight has not started')
          return
        }
        unregisterErrorCallback()
        hasInitCrashSight = false
        strategyEnableState = StrategyEnableState.Unknow
        console.log('[CrashSight][INFO] CrashSight stop success')
      },

      setUserId: function (_userId) {
        userId = _userId
      },

      setExtKV: function (key, value) {
        if (key) {
          extKV[key] = value
        }
      },

      clearExtKV: function () {
        extKV = {}
      },

      setAppVersion: function (_appVersion) {
        appVersion = _appVersion
      },

      setWXAppIdentify: function (_wxAppIdentify) {
        wxAppIdentify = _wxAppIdentify
      },

      reportException: async function (exceptionName, message, stack) {
        if (!hasInitCrashSight) {
          console.log('[CrashSight][Error] CrashSight has not started')
          return
        }

        if (strategyEnableState == StrategyEnableState.Disable) {
          console.log('[CrashSight][Error] CrashSight has disable by server')
          return
        }
        sendErrorMessage(exceptionName, message, stack)
      }
    }

    globalThis.__crashSight = crashSight

    // ========================== CrashSgiht Core End===============================



  },

  CS_Start: function (appId, reportURL) {
    if (globalThis.__crashSight && appId) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        appId = UTF8ToString(appId)
        reportURL = reportURL ? UTF8ToString(reportURL) : undefined
      }
      globalThis.__crashSight.start(appId, reportURL)
    }
  },


  CS_Stop: function () {
    if (globalThis.__crashSight) {
      globalThis.__crashSight.stop()
    }
  },

  CS_SetUserId: function (userId) {
    if (globalThis.__crashSight && userId) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        userId = UTF8ToString(userId)
      }
      globalThis.__crashSight.setUserId(userId)
    }
  },

  CS_SetExtKV: function (key, value) {
    if (globalThis.__crashSight && key) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        key = UTF8ToString(key)
        if (value) {
          value = UTF8ToString(value)
        } else {
          value = undefined
        }
      }
      globalThis.__crashSight.setExtKV(key, value)
    }
  },

  CS_ClearExtKV: function () {
    if (globalThis.__crashSight) {
      globalThis.__crashSight.clearExtKV()
    }
  },

  CS_SetAppVersion: function (appVersion) {
    if (globalThis.__crashSight && appVersion) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        appVersion = UTF8ToString(appVersion)
      }
      globalThis.__crashSight.setAppVersion(appVersion)
    }
  },

  CS_SetWXAppIdentify: function (wxAppIdentify) {
    if (globalThis.__crashSight && wxAppIdentify) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        wxAppIdentify = UTF8ToString(wxAppIdentify)
      }
      globalThis.__crashSight.setWXAppIdentify(wxAppIdentify)
    }
  },

  CS_ReportException: function (exceptionName, message, stack) {
    console.log("crashSight CS_ReportException")
    if (globalThis.__crashSight) {
      if (typeof globalThis.unityVersion !== 'undefined') {
        exceptionName = exceptionName ? UTF8ToString(exceptionName) : 'null';
        message = message ? UTF8ToString(message) : 'null'
        stack = stack ? UTF8ToString(stack) : 'null'
      }
      if (typeof message === 'undefined') {
        message = 'null'
      }
      if (typeof stack === 'undefined') {
        stack = 'null'
      }
      globalThis.__crashSight.reportException(exceptionName, message, stack)
    }
  },

  CS_JSBacktrace: function CS_JSBacktrace(skipCount, excludeFilter, limitCount) {
    let errObjForBacktrace = new Error()
    let backtrace = errObjForBacktrace.stack;
    if (typeof backtrace == 'string') {
      let lines = backtrace.split('\n');
      let resultLines = lines.length > skipCount ? lines.slice(skipCount) : lines;
      excludeFilter = excludeFilter ? UTF8ToString(excludeFilter) : null
      if (excludeFilter && resultLines && resultLines.length > 0) {
        let tmep = []
        let filters = excludeFilter.split('|')
        for (let i = 0; i < resultLines.length; i++) {
          let line = resultLines[i]
          let except = false
          for (let j = 0; j < filters.length; j++) {
            let filter = filters[j]
            if (line.indexOf(filter) != -1) {
              except = true
              break
            }
          }
          if (!except) {
            tmep.push(line)
          }
        }
        resultLines = tmep
      }

      if (limitCount > 0 && resultLines && resultLines.length > limitCount) {
        resultLines = resultLines.splice(0, limitCount)
      }
      let resultStr = resultLines.join('\n');
      if (resultStr.endsWith('\n')) {
        resultStr = resultStr.slice(0, -1);
      }
      let bufferSize = lengthBytesUTF8(resultStr) + 1;
      let buffer = _malloc(bufferSize);
      stringToUTF8(resultStr, buffer, bufferSize);
      return buffer;
    } else {
      return null
    }
  }

});

