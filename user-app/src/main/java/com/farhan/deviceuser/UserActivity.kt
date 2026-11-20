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
    var deviceId: String?
        get() = prefs.getString("device", null)
        private set(value) { prefs.edit().putString("device", value).apply() }
    private val deviceKey: String
        get() = prefs.getString("device_key", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_key", it).apply()
        }
    private val deviceToken: String
        get() = prefs.getString("device_token", null) ?: UUID.randomUUID().toString().also {
            prefs.edit().putString("device_token", it).apply()
        }

    private suspend fun request(method: String, path: String, body: JSONObject? = null, prefer: String? = null): String =
        withContext(Dispatchers.IO) {
            val builder = Request.Builder().url(API_URL + path)
                .addHeader("apikey", API_KEY)
                .addHeader("Authorization", "Bearer $API_KEY")
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

    fun forgetDevice() {
        deviceId = null
        prefs.edit().remove("device_token").apply()
    }

    suspend fun pair(code: String, context: Context) {
        require(code.length == 6 && code.all(Char::isDigit)) { "৬ সংখ্যার Pairing Code লিখুন।" }
        val payload = JSONObject()
            .put("p_code_hash", sha256(code))
            .put("p_device_key", deviceKey)
            .put("p_device_name", android.os.Build.DEVICE ?: "Android")
            .put("p_model", android.os.Build.MODEL ?: "Android")
            .put("p_android_version", android.os.Build.VERSION.RELEASE ?: "unknown")
            .put("p_app_version", "1.0.0")
        deviceId = request("POST", "/rest/v1/rpc/claim_pairing_code_anon", payload).trim().trim('"')
        heartbeat()
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
        val raw = request("POST", "/rest/v1/rpc/user_device_next_action",
            JSONObject().put("p_device_id", id).put("p_device_token_hash", sha256(deviceToken)))
        if (raw == "null" || raw.isBlank()) return null
        val item = JSONObject(raw)
        return PendingAction(item.getString("id"), item.getString("action_type"), item.optJSONObject("payload") ?: JSONObject())
    }

    suspend fun respond(action: PendingAction, allowed: Boolean) {
        request("POST", "/rest/v1/rpc/user_device_action_response",
            JSONObject().put("p_device_id", deviceId).put("p_device_token_hash", sha256(deviceToken))
                .put("p_action_id", action.id).put("p_status", if (allowed) "approved" else "denied"))
    }

    suspend fun complete(action: PendingAction) {
        request("POST", "/rest/v1/rpc/user_device_action_response",
            JSONObject().put("p_device_id", deviceId).put("p_device_token_hash", sha256(deviceToken))
                .put("p_action_id", action.id).put("p_status", "completed"))
    }

    suspend fun unpair() {
        val id = deviceId ?: return
        request("POST", "/rest/v1/rpc/user_device_unpair",
            JSONObject().put("p_device_id", id).put("p_device_token_hash", sha256(deviceToken)))
        forgetDevice()
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
    var pairingCode by remember { mutableStateOf("") }
    var message by remember { mutableStateOf("") }
    var pending by remember { mutableStateOf<PendingAction?>(null) }
    var connected by remember { mutableStateOf(api.deviceId != null) }

    LaunchedEffect(connected) {
        if (connected) {
            while (true) {
                try {
                    api.heartbeat()
                    if (pending == null) pending = api.nextAction()
                    message = "Connected • Keep this app open to receive requests"
                } catch (e: Exception) {
                    message = e.message ?: "Connection error"
                }
                delay(8000)
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Farhan Device Manager • User") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            if (!connected) {
                Text("কোনো Account বা Login লাগবে না। Admin App থেকে পাওয়া ৬ সংখ্যার Pairing Code লিখুন।")
                OutlinedTextField(pairingCode, { pairingCode = it.filter(Char::isDigit).take(6) },
                    label = { Text("Pairing Code") }, modifier = Modifier.fillMaxWidth())
                Button(enabled = pairingCode.length == 6, onClick = {
                    scope.launch {
                        try {
                            api.pair(pairingCode, context)
                            connected = true
                            message = "এই ফোনটি Admin-এর সঙ্গে যুক্ত হয়েছে।"
                        } catch (e: Exception) { message = e.message ?: "Pairing failed" }
                    }
                }) { Text("Connect phone") }
            } else {
                Text("এই ফোনটি Admin-এর সঙ্গে যুক্ত হয়েছে।")
                Text("Device: ${android.os.Build.MODEL}")
                Text("Admin-এর অনুরোধ এলে প্রতিবার আলাদা অনুমতি চাইবে।")
                Text("দূর থেকে অনুরোধ পেতে অ্যাপটি খোলা রাখুন। Android ব্যাকগ্রাউন্ডে অ্যাপ বন্ধ করলে সংযোগ থেমে যেতে পারে।")
                OutlinedButton(onClick = {
                    scope.launch {
                        try { api.unpair(); connected = false; pending = null; message = "Unpaired" }
                        catch (e: Exception) { message = e.message ?: "Unpair failed" }
                    }
                }) { Text("Disconnect / Unpair") }
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
