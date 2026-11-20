package com.farhan.deviceuser

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
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
import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
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
    val deviceId get() = prefs.getString("device_id", null)
    private val tokenHash get() = prefs.getString("device_token_hash", null)

    private suspend fun rpc(name: String, body: JSONObject): String = withContext(Dispatchers.IO) {
        val req = Request.Builder().url("$API_URL/rest/v1/rpc/$name")
            .addHeader("apikey", API_KEY)
            .addHeader("Authorization", "Bearer $API_KEY")
            .addHeader("Content-Type", "application/json")
            .post(body.toString().toRequestBody(JSON_TYPE)).build()
        http.newCall(req).execute().use { response ->
            val text = response.body?.string().orEmpty()
            if (!response.isSuccessful) error("HTTP ${response.code}: $text")
            text
        }
    }

    suspend fun pair(code: String, context: Context) {
        require(code.length == 6 && code.all(Char::isDigit)) { "৬ সংখ্যার Pairing Code লিখুন।" }
        val deviceSecret = ByteArray(32).also { SecureRandom().nextBytes(it) }.joinToString("") { "%02x".format(it) }
        val hash = sha256(code)
        val secretHash = sha256(deviceSecret)
        val result = rpc("claim_pairing_code_anon", JSONObject()
            .put("p_code_hash", hash)
            .put("p_device_key", UUID.randomUUID().toString())
            .put("p_device_token_hash", secretHash)
            .put("p_device_name", android.os.Build.DEVICE ?: "Android")
            .put("p_model", android.os.Build.MODEL ?: "Android")
            .put("p_android_version", android.os.Build.VERSION.RELEASE ?: "unknown")
            .put("p_app_version", "1.0.0")).trim().trim('"')
        prefs.edit().putString("device_id", result).putString("device_token_hash", secretHash).apply()
        heartbeat()
    }

    suspend fun heartbeat() {
        val id = deviceId ?: return
        val hash = tokenHash ?: error("Device key missing. Pair again.")
        val ok = rpc("user_device_heartbeat", JSONObject()
            .put("p_device_id", id).put("p_device_token_hash", hash)).trim()
        if (ok != "true") error("Device connection rejected")
    }

    suspend fun nextAction(): PendingAction? {
        val id = deviceId ?: return null
        val hash = tokenHash ?: error("Device key missing")
        val raw = rpc("user_device_next_action", JSONObject()
            .put("p_device_id", id).put("p_device_token_hash", hash)).trim()
        if (raw.isBlank() || raw == "null") return null
        val obj = JSONObject(raw)
        return PendingAction(obj.getString("id"), obj.getString("action_type"), obj.optJSONObject("payload") ?: JSONObject())
    }

    suspend fun respond(action: PendingAction, status: String) {
        val id = deviceId ?: error("Not paired")
        val hash = tokenHash ?: error("Device key missing")
        val ok = rpc("user_device_action_response", JSONObject()
            .put("p_device_id", id).put("p_device_token_hash", hash)
            .put("p_action_id", action.id).put("p_status", status)).trim()
        if (ok != "true") error("Action expired or already handled")
    }

    suspend fun unpair() {
        val id = deviceId ?: return
        val hash = tokenHash ?: error("Device key missing")
        rpc("user_device_unpair", JSONObject().put("p_device_id", id).put("p_device_token_hash", hash))
        prefs.edit().remove("device_id").remove("device_token_hash").apply()
    }

    private fun sha256(value: String) = MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray()).joinToString("") { "%02x".format(it) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun UserScreen(context: Context) {
    val api = remember { UserApi(context) }
    val scope = rememberCoroutineScope()
    var pairingCode by remember { mutableStateOf("") }
    var paired by remember { mutableStateOf(api.deviceId != null) }
    var message by remember { mutableStateOf("এই ফোনটি Admin-এর সঙ্গে যুক্ত করতে Pairing Code দিন।") }
    var pending by remember { mutableStateOf<PendingAction?>(null) }

    LaunchedEffect(paired) {
        if (paired) {
            while (true) {
                try {
                    api.heartbeat()
                    if (pending == null) pending = api.nextAction()
                    message = "Connected • Admin request-এর জন্য অপেক্ষা করছে"
                } catch (e: Exception) {
                    message = e.message ?: "Connection error"
                }
                delay(8000)
            }
        }
    }

    Scaffold(topBar = { TopAppBar(title = { Text("Farhan Device Manager • User") }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding).padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
            if (!paired) {
                Text("কোনো Account, Email বা Login লাগবে না। Admin App থেকে পাওয়া ৬ সংখ্যার Pairing Code লিখুন।")
                OutlinedTextField(
                    value = pairingCode,
                    onValueChange = { pairingCode = it.filter(Char::isDigit).take(6) },
                    label = { Text("6-digit Pairing Code") },
                    modifier = Modifier.fillMaxWidth()
                )
                Button(
                    enabled = pairingCode.length == 6,
                    onClick = {
                        scope.launch {
                            try {
                                api.pair(pairingCode, context)
                                paired = true
                                message = "এই ফোনটি Admin-এর সঙ্গে যুক্ত হয়েছে।"
                            } catch (e: Exception) {
                                message = e.message ?: "Pairing failed"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Connect to Admin") }
            } else {
                Text("এই ফোনটি Admin-এর সঙ্গে যুক্ত।")
                Text("Device: ${android.os.Build.MODEL}")
                Text("Remote request এলে এই অ্যাপে Allow বা Deny করতে পারবেন।")
                Text("App-টি খোলা রাখুন। Background-এ সবসময় চলার নিশ্চয়তা নেই।")
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            try {
                                api.unpair()
                                paired = false
                                pending = null
                                message = "এই ফোনটি Unpair করা হয়েছে।"
                            } catch (e: Exception) {
                                message = e.message ?: "Unpair failed"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Unpair this phone") }
            }
            Text(message)
        }
    }

    pending?.let { action ->
        val description = when (action.type) {
            "open_dialer" -> "Admin আপনার Dialer খুলতে চায়। কোনো কল করা হবে না।"
            "compose_sms" -> "Admin SMS composer খুলতে চায়। Message দেখে Send আপনাকেই চাপতে হবে।"
            "open_app" -> "Admin এই App খুলতে চায়: ${action.payload.optString("package")}"
            "disconnect" -> "Admin এই ফোনটি Disconnect করতে চায়।"
            else -> "Requested action: ${action.type}"
        }
        AlertDialog(
            onDismissRequest = {},
            title = { Text("এই কাজটি অনুমতি দেবেন?") },
            text = { Text(description) },
            confirmButton = {
                TextButton(onClick = {
                    scope.launch {
                        try {
                            api.respond(action, "approved")
                            when (action.type) {
                                "open_dialer" -> context.startActivity(Intent(Intent.ACTION_DIAL,
                                    Uri.parse("tel:${Uri.encode(action.payload.optString("number"))}")))
                                "compose_sms" -> context.startActivity(Intent(Intent.ACTION_SENDTO,
                                    Uri.parse("smsto:${Uri.encode(action.payload.optString("number"))}"))
                                    .putExtra("sms_body", action.payload.optString("body")))
                                "open_app" -> context.packageManager.getLaunchIntentForPackage(
                                    action.payload.optString("package"))?.let { context.startActivity(it) }
                                "disconnect" -> { api.unpair(); paired = false }
                            }
                            if (action.type != "disconnect") api.respond(action, "completed")
                        } catch (e: Exception) {
                            message = e.message ?: "Action failed"
                        }
                        pending = null
                    }
                }) { Text("Allow") }
            },
            dismissButton = {
                TextButton(onClick = {
                    scope.launch {
                        try { api.respond(action, "denied") } catch (_: Exception) {}
                        pending = null
                    }
                }) { Text("Deny") }
            }
        )
    }
}
