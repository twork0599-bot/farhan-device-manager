package com.farhan.deviceuser

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

private const val API_URL = "https://gnnfmzrrfchyoscmbkrr.supabase.co"
private const val API_KEY = "sb_publishable_GKmt-gxRR3I9NC4PYapTgA_sey3owO8"
private val JSON_TYPE = "application/json; charset=utf-8".toMediaType()

class UserActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { UserScreen(this) } }
    }
}

private data class PendingAction(val id: String, val type: String, val payload: JSONObject)

private class UserApi(context: Context) {
    private val prefs = context.getSharedPreferences("fdm_user", Context.MODE_PRIVATE)
    private val http = OkHttpClient()
    var token: String?
        get() = prefs.getString("token", null)
        private set(value) { prefs.edit().putString("token", value).apply() }
    var userId: String?
        get() = prefs.getString("uid", null)
        private set(value) { prefs.edit().putString("uid", value).apply() }
    var deviceId: String?
        get() = prefs.getString("device", null)
        private set(value) { prefs.edit().putString("device", value).apply() }
    private val deviceKey: String
        get() = prefs.getString("device_key", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_key", it).apply()
        }

    private suspend fun request(method: String, path: String, body: JSONObject? = null, prefer: String? = null): String =
        withContext(Dispatchers.IO) {
            val builder = Request.Builder().url(API_URL + path)
                .addHeader("apikey", API_KEY)
                .addHeader("Authorization", "Bearer ${token ?: API_KEY}")
                .addHeader("Accept", "application/json")
            if (prefer != null) builder.addHeader("Prefer", prefer)
            val requestBody = body?.toString()?.toRequestBody(JSON_TYPE)
            when (method) {
                "GET" -> builder.get()
                "POST" -> builder.post(requestBody ?: "{}".toRequestBody(JSON_TYPE))
                "PATCH" -> builder.patch(requestBody ?: "{}".toRequestBody(JSON_TYPE))
                else -> error("Unsupported request")
            }
            http.newCall(builder.build()).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful) error("HTTP ${response.code}: $text")
                text
            }
        }

    suspend fun authenticate(email: String, password: String, signup: Boolean) {
        val clean = email.trim()
        require(android.util.Patterns.EMAIL_ADDRESS.matcher(clean).matches()) { "সঠিক Email address লিখুন।" }
        require(password.length >= 6) { "Password কমপক্ষে ৬ অক্ষরের হতে হবে।" }
        val path = if (signup) "/auth/v1/signup" else "/auth/v1/token?grant_type=password"
        val result = JSONObject(request("POST", path, JSONObject().put("email", clean).put("password", password)))
        if (result.has("access_token")) {
            token = result.getString("access_token")
            userId = result.getJSONObject("user").getString("id")
        } else if (signup && result.has("user") && !result.isNull("user")) {
            error("অ্যাকাউন্ট তৈরি হয়েছে। Email inbox থেকে confirmation সম্পন্ন করে Sign in করুন।")
        } else error("Authentication failed")
    }

    fun signOut() {
        token = null
        userId = null
        deviceId = null
    }

    suspend fun pair(code: String, context: Context) {
        require(code.length == 6 && code.all(Char::isDigit)) { "৬ সংখ্যার Pairing Code লিখুন।" }
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = context.packageManager.queryIntentActivities(launcher, 0)
            .map { it.activityInfo.packageName }.distinct().take(80)
        val payload = JSONObject()
            .put("p_code_hash", sha256(code))
            .put("p_device_key", deviceKey)
            .put("p_device_name", android.os.Build.DEVICE ?: "Android")
            .put("p_model", android.os.Build.MODEL ?: "Android")
            .put("p_android_version", android.os.Build.VERSION.RELEASE ?: "unknown")
            .put("p_app_version", "1.0.0")
        deviceId = request("POST", "/rest/v1/rpc/claim_pairing_code", payload).trim().trim('"')
        heartbeat(apps)
    }

    suspend fun heartbeat() {
        val id = deviceId ?: return
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps = appContext?.packageManager?.queryIntentActivities(launcher, 0)
            ?.map { it.activityInfo.packageName }?.distinct()?.take(80) ?: emptyList()
        request("PATCH", "/rest/v1/devices?id=eq.$id",
            JSONObject().put("status", "online").put("last_seen_at", Instant.now().toString())
                .put("installed_apps", JSONArray(apps)), "return=minimal")
    }

    suspend fun nextAction(): PendingAction? {
        val id = deviceId ?: return null
        val expiry = java.net.URLEncoder.encode(Instant.now().toString(), "UTF-8")
        val array = JSONArray(request("GET", "/rest/v1/action_requests?select=id,action_type,payload&device_id=eq.$id&status=eq.pending&expires_at=gt.$expiry&order=requested_at.asc&limit=1"))
        if (array.length() == 0) return null
        val item = array.getJSONObject(0)
        return PendingAction(item.getString("id"), item.getString("action_type"), item.optJSONObject("payload") ?: JSONObject())
    }

    suspend fun respond(action: PendingAction, allowed: Boolean) {
        val values = JSONObject().put("status", if (allowed) "approved" else "denied")
        if (allowed) values.put("consented_at", Instant.now().toString())
        request("PATCH", "/rest/v1/action_requests?id=eq.${action.id}", values, "return=minimal")
    }

    suspend fun complete(action: PendingAction) {
        request("PATCH", "/rest/v1/action_requests?id=eq.${action.id}",
            JSONObject().put("status", "completed").put("completed_at", Instant.now().toString()), "return=minimal")
    }

    suspend fun unpair() {
        val id = deviceId ?: return
        request("PATCH", "/rest/v1/devices?id=eq.$id",
            JSONObject().put("status", "revoked").put("revoked_at", Instant.now().toString()), "return=minimal")
        deviceId = null
    }

    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray()).joinToString("") { "%02x".format(it) }

    companion object {
        var appContext: Context? = null
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun UserScreen(context: Context) {
    UserApi.appContext = context.applicationContext
    val api = remember { UserApi(context) }
    val scope = rememberCoroutineScope()
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var signedIn by remember { mutableStateOf(api.token != null && api.userId != null) }
    var pairingCode by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<PendingAction?>(null) }

    LaunchedEffect(signedIn, api.deviceId) {
        if (signedIn && api.deviceId != null) {
            while (true) {
                try {
                    api.heartbeat()
                    if (pending == null) pending = api.nextAction()
                    message = "Connected • Foreground monitoring active"
                } catch (e: Exception) {
                    message = e.message ?: "Connection error"
                }
                delay(8000)
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Farhan Device Manager • User") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (!signedIn) {
                Text("এই ফোনটি Admin-এর সঙ্গে যুক্ত করতে আপনার অ্যাকাউন্টে Sign in করুন। Admin ও User ফোনে একই অ্যাকাউন্ট ব্যবহার করুন।")
                OutlinedTextField(email, { email = it }, label = { Text("Email") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(password, { password = it }, label = { Text("Password") }, modifier = Modifier.fillMaxWidth())
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { scope.launch { try { api.authenticate(email, password, false); signedIn = true; message = "Signed in" } catch (e: Exception) { message = e.message ?: "Sign in failed" } } }) { Text("Sign in") }
                    OutlinedButton(onClick = { scope.launch { try { api.authenticate(email, password, true); if (api.token != null) signedIn = true; message = "Account created. Check email if confirmation is required." } catch (e: Exception) { message = e.message ?: "Sign up failed" } } }) { Text("Sign up") }
                }
            } else if (api.deviceId == null) {
                Text("Enter the 6-digit pairing code shown in the Admin app.")
                OutlinedTextField(pairingCode, { pairingCode = it.filter(Char::isDigit).take(6) },
                    label = { Text("Pairing Code") }, modifier = Modifier.fillMaxWidth())
                Button(enabled = pairingCode.length == 6, onClick = {
                    scope.launch { try { api.pair(pairingCode, context); message = "Phone paired successfully." } catch (e: Exception) { message = e.message ?: "Pairing failed" } }
                }) { Text("Pair this phone") }
                TextButton(onClick = { api.signOut(); signedIn = false }) { Text("Sign out") }
            } else {
                Text("This phone is paired with the Admin account.")
                Text("Device: ${android.os.Build.MODEL}")
                Text("Keep this app open while you want to receive requests.")
                OutlinedButton(onClick = { scope.launch { try { api.unpair(); message = "This phone has been unpaired." } catch (e: Exception) { message = e.message ?: "Unpair failed" } } }) { Text("Unpair this phone") }
                TextButton(onClick = { api.signOut(); signedIn = false }) { Text("Sign out") }
            }
            if (message.isNotBlank()) Text(message)
        }
    }

    pending?.let { action ->
        val description = when (action.type) {
            "open_dialer" -> "Admin wants to open your phone dialer. No call will be placed."
            "compose_sms" -> "Admin wants to open the SMS composer. You must review and tap Send yourself."
            "open_app" -> "Admin wants to open app: ${action.payload.optString("package")}."
            "disconnect" -> "Admin wants to disconnect this device."
            else -> "Requested action: ${action.type}"
        }
        AlertDialog(onDismissRequest = {}, title = { Text("Allow this action?") }, text = { Text(description) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try {
                            api.respond(action, true)
                            when (action.type) {
                                "open_dialer" -> context.startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:${Uri.encode(action.payload.optString("number"))}")))
                                "compose_sms" -> context.startActivity(Intent(Intent.ACTION_SENDTO, Uri.parse("smsto:${Uri.encode(action.payload.optString("number"))}")).putExtra("sms_body", action.payload.optString("body")))
                                "open_app" -> context.packageManager.getLaunchIntentForPackage(action.payload.optString("package"))?.let { context.startActivity(it) }
                                "disconnect" -> api.unpair()
                            }
                            api.complete(action)
                        } catch (e: Exception) { message = e.message ?: "Action failed" }
                        pending = null
                    }
                }) { Text("Allow") }
            },
            dismissButton = {
                TextButton(onClick = { scope.launch { try { api.respond(action, false) } catch (_: Exception) {} ; pending = null } }) { Text("Deny") }
            }
        )
    }
}
