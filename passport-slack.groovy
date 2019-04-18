package ru.ratauth.admin.handlers

@Grab(group = "com.auth0", module = "java-jwt", version = "3.3.0")
import com.auth0.jwt.JWT

@Grab(group = 'com.mashape.unirest', module = 'unirest-java', version = '1.4.9')
import com.mashape.unirest.http.Unirest
import groovy.json.JsonOutput
import groovy.json.JsonSlurper
import org.apache.http.conn.ssl.SSLConnectionSocketFactory
import org.apache.http.conn.ssl.TrustSelfSignedStrategy
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import ratpack.jackson.Jackson

import javax.net.ssl.SSLContext
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.DateFormat
import java.util.concurrent.ConcurrentHashMap

@Grab("io.ratpack:ratpack-groovy:1.5.0")
import static ratpack.groovy.Groovy.ratpack
import static ratpack.jackson.Jackson.json

println("Starting".center(50, "="))

// init
SSLContext sslcontext = SSLContexts.custom()
        .loadTrustMaterial(null, new TrustSelfSignedStrategy())
        .build()
SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
CloseableHttpClient httpclient = HttpClients.custom()
        .setSSLSocketFactory(sslsf)
        .build()
Unirest.setHttpClient(httpclient)
def delayedResponses = [:] as ConcurrentHashMap

ratpack {
    serverConfig {
        port 5051
    }

    handlers {
        get("passport-color") {
            try {
                String action = request.queryParams.text
                println action
                println("[${request.queryParams['user_name']} from ${request.queryParams['channel_name']}] ${action}")
                def color = fetchColor()
                if (!(request.queryParams['channel_name'] in ["passport-support", "passport_team"])) {
                    render(json(attachments:
                            [[
                                     text : "Запрещено вызывать команду отсюда! Все команды должны вызываться из #passport-support" as String,
                                     color: colorToHex(color),
                             ]]
                    ))
                    return
                }


                if(System.currentTimeMillis() % 50 == 0) {
                    render(json(attachments:
                            [[
                                     response_type: "in_channel",
                                     text : "Голем сделает. 10 баксов, деньги вперед",
                                     color: colorToHex(color),
                             ]]
                    ))
                    return
                }

                if (action in ["color", "server-color"]) {

                    render(json(attachments:
                            [[
                                     mrkdwn_in: ["text"],
                                     title: "Текущий цвет",
                                     text : "*dev*: ${localizeColor(color)}\n*prod*: ${localizeColor(fetchProdColor())}" as String,
                                     color: colorToHex(color),
                             ]]
                    ))
                } else if (action.startsWith("check-password")) {
                    def parameters = action["check-password".length()..-1].trim()
                    def (clientId, password) = parameters.split(" ")
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/passport-admin-api/authclients/${clientId}")
                            .basicAuth("admin", "pass")
                            .asString()

                    if (response.status == 404) {
                        render(json(
                                attachments:
                                        [[
                                                 text : "Клиент ${clientId} не существует" as String,
                                                 color: colorToHex(color),
                                         ]]
                        ))
                        return
                    }

                    def responseJson = new JsonSlurper().parseText(response.body)
                    def rp = responseJson.authClients[0]

                    render(json(
                            attachments:
                                    [[
                                             text : hashPassword(password, rp.salt)
                                                     .equalsIgnoreCase(rp.password) ? "Пароль совпадает" : "Пароль не совпадает",
                                             color: colorToHex(color),
                                     ]]
                    ))

                } else if (action.startsWith("help")) {
                    render(json(
                            attachments:
                                    [[
                                             text : """
*color* - вывести текущий активный цвет
*show-client* <client-id> - вывести информацию по выбранному клиенту
*check-password* <client-id> <password> - проверить правильность пароля по клиенту
*show-tokens* <user-id> - вывести токены из последней сессии по пользователю
*show-userinfo* <user-id> - вывести userInfo (данные, которые будут переданы в id-токене)
*restart* <приложение> - перезагрузить приложение (можно опустить цвет)
*activator-version* <activator-idp> - версия IDP провайдера на /activate
*verifier-version* <verifier-idp> - версия IDP провайдера на /verify
""",
                                             mrkdwn_in: ["text"],
                                             color: colorToHex(color),
                                     ]]
                    ))
                } else if (action.startsWith("restart")) {
                    def appId = action["restart".length()..-1].trim()
                    if(!appId.endsWith("-green") && !appId.endsWith("-blue") && !appId.endsWith("-red")) {
                        appId = "${appId}-${color}"
                    }

                    def response = Unirest.post("https://testsense.alfabank.ru/marathon/v2/apps/passport/${appId}/restart")
                            .basicAuth("external", "5bxB2N24P5872P9d867x")
                            .header("Content-Type", "application/json")
                            .asJson()

                    if(response.status == 200){
                        render(json(
                                response_type: "in_channel",
                                attachments:
                                        [[
                                                 text : "Перезагружается ${appId}" as String,
                                                 color: colorToHex(color),
                                         ]]
                        ))
                    } else {
                        render(json(
                                attachments:
                                        [[
                                                 text : "Ошибка: ${response.status} (${response.body})" as String,
                                                 color: colorToHex(color),
                                         ]]
                        ))
                    }
                } else if (action.startsWith("show-session")) {

                    def userId = action["show-session".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/passport-admin-api/sessions?user_id=${userId}&limit=1")
                            .asString()

                    if (response.status == 404) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }

                    def sessions = new JsonSlurper().parseText(response.body).sessions
                    if(sessions.size() == 0) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }
                    def session = new JsonSlurper().parseText(response.body).sessions[0]

                    render(json(
                            response_type: "in_channel",
                            attachments:
                                    [[
                                             title: userId,
                                             text: JsonOutput.prettyPrint(JsonOutput.toJson(session)),
                                             mrkdwn_in: ["text"],
                                             color: colorToHex(color),
                                     ]]
                    ))


                } else if (action.startsWith("activator-version")) {
                    def idp = action["activator-version".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/openid-green/providers/${idp}/activator/version")
                            .asString()

                    def responseProd = Unirest.get("https://sense.alfabank.ru/passport/openid-green/providers/${idp}/activator/version")
                            .asString()

                    render(json(
                            attachments:
                                    [[
                                             text: "*Версия активатора для ${idp}:*\n *dev:* ${getVersion(response)}\n *prod:* ${getVersion(responseProd)}" as String,
                                             color: colorToHex(color),
                                     ]]
                    ))

                } else if (action.startsWith("verifier-version")) {
                    def idp = action["verifier-version".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/openid-green/providers/${idp}/verifier/version")
                            .asString()

                    def responseProd = Unirest.get("https://sense.alfabank.ru/passport/openid-green/providers/${idp}/verifier/version")
                            .asString()

                    render(json(
                            attachments:
                                    [[
                                             text: "*Версия верификатора для ${idp}:*\n *dev:* ${getVersion(response)}\n *prod:* ${getVersion(responseProd)}" as String,
                                             color: colorToHex(color),
                                     ]]
                    ))

                } else if (action.startsWith("show-userinfo")) {

                    def userId = action["show-userinfo".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/passport-admin-api/sessions?user_id=${userId}&limit=1")
                            .asString()

                    if (response.status == 404) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }

                    def sessions = new JsonSlurper().parseText(response.body).sessions
                    if(sessions.size() == 0) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }
                    def session = new JsonSlurper().parseText(response.body).sessions[0]

                    render(json(
                            response_type: "in_channel",
                            attachments:
                                    [[
                                             title: userId,
                                             text: JWT.decode(session.userInfo).claims.collect({ "${it.key}: ${it.value.asString()}"}).join("\n"),
                                             color: colorToHex(color),
                                     ]]
                    ))

                } else if (action.startsWith("delayed-response")) {
                    def uuid = action["delayed-response".length()..-1].trim()
                    if(!delayedResponses[uuid]) {
                        status 200
                    } else {
                        render json(delayedResponses[uuid])
                    }
                } else if (action.startsWith("create-user")) {

                    def uuid = UUID.randomUUID().toString()
                    render(json(
                            response_url: "https://chest.one/passport-color?text=delayed-response ${uuid}" as String,
                            trigger_id: uuid,
                            attachments:
                                    [[
                                             text : "Ожидаем ответ...",
                                             color: colorToHex(color),
                                     ]]
                    ))

                    def response = Unirest.get("https://testsense.alfabank.ru/mobile/autotests/am-user/create")
                            .header("Content-Type", "application/json")
                            .header("TokenForCreatingAMUser", "Bearer eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiJhbGZhbGFidGVzdCIsImV4cCI6MTU2MjY2MzA4OX0.D-lqS8OM5WRkixtU3a1pbovRe_5yTr2ckm65z2pA1jT9PXxrVUjgexrjwwAVdaI5ozrAl1dBAQH2jho1qDFMIA")
                            .asString()

                    assert response.status == 200
                    def json = new JsonSlurper().parseText(response.body)


                    String responseText = """
${json.fullName} [cus: ${json.customerId}, login: ${json.login}]
+${json.phoneNumber}
${json.accounts*.accountNumberFull.join("\n")}
"""
                    delayedResponses.put(uuid,
                            response_type: "in_channel",
                            attachments:
                                    [[
                                             text : responseText,
                                             color: colorToHex(color),
                                     ]] as HashMap
                    )

                } else if (action.startsWith("show-tokens")) {

                    def userId = action["show-tokens".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/passport-admin-api/sessions?user_id=${userId}&limit=1")
                            .asString()

                    if (response.status == 404) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }

                    def entries = []
                    def sessions = new JsonSlurper().parseText(response.body).sessions
                    if(sessions.size() == 0) {
                        render(json(attachments:
                                [[
                                         text : "Для пользователя ${userId} не найдено сессий" as String,
                                         color: colorToHex(color),
                                 ]]
                        ))
                        return
                    }
                    def session = new JsonSlurper().parseText(response.body).sessions[0]

                    session.entries.each { entry ->

                        def text = ""
                        def tokens = entry.tokens.collect({
                            "*${it.token}* ${dateFromMills(it.expiresIn)}" as String
                        }).reverse().join("\n")
                        if(tokens) {
                            text += "tokens/expiration\n${tokens}\n"
                        }

                        def refreshTokens = entry.tokens.collect({
                            "*${it.refreshToken}* ${dateFromMills(it.refreshTokenExpiresIn)}" as String
                        }).reverse().join("\n")
                        if(refreshTokens) {
                            text += "\nrefresh tokens/expiration\n${refreshTokens}"
                        }

                        entries << [
                                mrkdwn_in: ["text"],
                                title: entry.relyingParty,
                                text : """
code = ${entry.authCode}
refreshToken = ${entry.refreshToken}

${text}"""
                                        .stripIndent()
                                        .stripMargin(),
                                color: colorToHex(color),
                        ]
                    }

                    render(json(
                            text: "Сессия ${userId} за ${dateFromMills(session.created)}" as String,
                            attachments: entries
                    ))


                } else if (action.startsWith("show-client")) {

                    def clientId = action["show-client".length()..-1].trim()
                    def response = Unirest.get("https://testsense.alfabank.ru/passport/passport-admin-api/authclients/${clientId}")
                            .asJson()

                    if (response.status == 404) {
                        render(json(
                                response_type: "in_channel",
                                attachments:
                                        [[
                                                 text : "Клиент ${clientId} не существует" as String,
                                                 color: colorToHex(color),
                                         ]]
                        ))
                        return
                    }

                    def client = response
                            .body
                            .object
                            .getJSONArray("authClients")[0]

                    def props = []
                    for (def key : client.keySet()) {
                        props << "${key}: ${client[key]}"
                    }

                    render(json(
                            response_type: "in_channel",
                            attachments:
                                    [[
                                             title: clientId,
                                             text: "```" + props.join("\n") + "```",
                                             mrkdwn_in: ["text"],
                                             color: colorToHex(color),
                                     ]]
                    ))
                } else {
                    render(json(attachments:
                            [[
                                     // Ты создал голема, и не понимаешь его чувства
                                     // * тяжело дышит *
                                     // почему я жгу?
                                     // я не робот, я голем
                                     text : "${action}? Голем не понимает" as String,
                                     color: colorToHex(color),
                             ]]
//                                     text : "${action}? Голем не понимает" as String,
//                                     color: colorToHex(color),
//                             ]]
                    ))
                }

            } catch (e) {
                e.printStackTrace()
            }
        }

        get('health') {
            render 'ok'
        }
    }

}

static getVersion(response) {
    if (response.status == 404) {
        return "не найден"
    }
    return new JsonSlurper().parseText(response.body).version
}

static colorToHex(color) {
    color == "blue" ? "#7ec0ee" : color == "green" ? "#58c790" : "#000000"
}

static fetchColor() {
    Unirest.get("https://testsense.alfabank.ru/passport/color").asJson().body.object.passportEnvColor
}

static fetchProdColor() {
    Unirest.get("https://sense.alfabank.ru/passport/color").asJson().body.object.passportEnvColor
}

static localizeColor(color) {
    color == "blue" ? "синий" : color == "green" ? "зеленый" : color
}

static dateFromMills(mills) {
    Calendar calendar = Calendar.instance
    calendar.timeInMillis = mills
    return DateFormat.dateTimeInstance.format(calendar.time)
}

static String hashPassword(String password, String salt) {
    MessageDigest digest = MessageDigest.getInstance("SHA-256")
    byte[] saltBytes = salt.decodeBase64()
    byte[] allBytes = (password.getBytes(StandardCharsets.UTF_8) as List) + (saltBytes as List)
    byte[] hash = digest.digest(allBytes)
    return Base64.encoder.encodeToString(hash)
}

println("Started".center(50, "="))