package com.farhan.ethicalmanager

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.time.Instant
import java.util.UUID

private const val URL = "https://gnnfmzrrfchyoscmbkrr.supabase.co"
private const val KEY = "sb_publishable_GKmt-gxRR3I9NC4PYapTgA_sey3owO8"
private val JSON = "application/json; charset=utf-8".toMediaType()

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { DeviceManager(this) } }
    }
}

private data class Phone(val id:String,val name:String,val model:String,val status:String,val seen:String,val apps:List<String>)
private data class Action(val id:String,val type:String,val payload:JSONObject)

private class Api(ctx:Context) {
    private val prefs=ctx.getSharedPreferences("fdm",Context.MODE_PRIVATE)
    private val http=OkHttpClient()
    var token:String? get()=prefs.getString("token",null); private set(v){prefs.edit().putString("token",v).apply()}
    var uid:String? get()=prefs.getString("uid",null); private set(v){prefs.edit().putString("uid",v).apply()}
    var deviceId:String? get()=prefs.getString("device",null); set(v){prefs.edit().putString("device",v).apply()}
    private val deviceKey get()=prefs.getString("device_key",null)?:UUID.randomUUID().toString().also{prefs.edit().putString("device_key",it).apply()}
    private suspend fun req(method:String,path:String,body:JSONObject?=null,prefer:String?=null):String=withContext(Dispatchers.IO){
        val b=Request.Builder().url(URL+path).addHeader("apikey",KEY).addHeader("Authorization","Bearer ${token?:KEY}").addHeader("Accept","application/json")
        if(prefer!=null)b.addHeader("Prefer",prefer)
        val rb=body?.toString()?.toRequestBody(JSON)
        when(method){"GET"->b.get();"POST"->b.post(rb?: "{}".toRequestBody(JSON));"PATCH"->b.patch(rb?: "{}".toRequestBody(JSON));else->error("Unsupported")}
        http.newCall(b.build()).execute().use{r->val s=r.body?.string().orEmpty();if(!r.isSuccessful)error("HTTP ${r.code}: $s");s}
    }
    suspend fun auth(email:String,password:String,signup:Boolean){
        val path=if(signup)"/auth/v1/signup" else "/auth/v1/token?grant_type=password"
        val j=JSONObject(req("POST",path,JSONObject().put("email",email).put("password",password)))
        if(j.has("access_token")){token=j.getString("access_token");uid=j.getJSONObject("user").getString("id")}
        else if(!signup) error("Login failed")
    }
    fun signOut(){token=null;uid=null;deviceId=null}
    suspend fun invite():String{
        val c=(100000..999999).random().toString()
        val hash=sha(c)
        req("POST","/rest/v1/pairing_invites",JSONObject().put("owner_id",uid).put("code_hash",hash).put("expires_at",Instant.now().plusSeconds(600).toString()),"return=minimal")
        return c
    }
    suspend fun pair(code:String,ctx:Context){
        val intent=Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        val apps=ctx.packageManager.queryIntentActivities(intent,0).map{it.activityInfo.packageName}.distinct().take(80)
        val b=JSONObject().put("p_code_hash",sha(code.trim())).put("p_device_key",deviceKey)
            .put("p_device_name",android.os.Build.DEVICE?: "Android").put("p_model",android.os.Build.MODEL?: "Android")
            .put("p_android_version",android.os.Build.VERSION.RELEASE?: "unknown").put("p_app_version","1.0.0")
        deviceId=req("POST","/rest/v1/rpc/claim_pairing_code",b).trim().trim('"')
        heartbeat(apps)
    }
    suspend fun phones():List<Phone>{
        val a=JSONArray(req("GET","/rest/v1/devices?select=id,device_name,model,status,last_seen_at,installed_apps&order=created_at.desc"))
        return (0 until a.length()).map{ i->val x=a.getJSONObject(i);val ar=x.optJSONArray("installed_apps")?:JSONArray()
            Phone(x.getString("id"),x.optString("device_name"),x.optString("model"),x.optString("status"),x.optString("last_seen_at"),(0 until ar.length()).map{ar.optString(it)})}
    }
    suspend fun heartbeat(apps:List<String>){
        val id=deviceId?:return
        req("PATCH","/rest/v1/devices?id=eq.$id",JSONObject().put("status","online").put("last_seen_at",Instant.now().toString()).put("installed_apps",JSONArray(apps.take(80))),"return=minimal")
    }
    suspend fun send(p:Phone,type:String,payload:JSONObject=JSONObject()){
        req("POST","/rest/v1/action_requests",JSONObject().put("owner_id",uid).put("device_id",p.id).put("action_type",type).put("payload",payload).put("requires_consent",true),"return=minimal")
    }
    suspend fun pending():Action?{
        val id=deviceId?:return null
        val a=JSONArray(req("GET","/rest/v1/action_requests?select=id,action_type,payload&device_id=eq.$id&status=eq.pending&expires_at=gt.${java.net.URLEncoder.encode(Instant.now().toString(),"UTF-8")}&order=requested_at.asc&limit=1"))
        if(a.length()==0)return null
        val x=a.getJSONObject(0);return Action(x.getString("id"),x.getString("action_type"),x.optJSONObject("payload")?:JSONObject())
    }
    suspend fun respond(a:Action,allow:Boolean){
        val b=JSONObject().put("status",if(allow)"approved" else "denied")
        if(allow)b.put("consented_at",Instant.now().toString())
        req("PATCH","/rest/v1/action_requests?id=eq.${a.id}",b,"return=minimal")
    }
    suspend fun complete(a:Action){req("PATCH","/rest/v1/action_requests?id=eq.${a.id}",JSONObject().put("status","completed").put("completed_at",Instant.now().toString()),"return=minimal")}
    suspend fun revoke(){val id=deviceId?:return;req("PATCH","/rest/v1/devices?id=eq.$id",JSONObject().put("status","revoked").put("revoked_at",Instant.now().toString()),"return=minimal");deviceId=null}
    private fun sha(s:String)=MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString(""){"%02x".format(it)}
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun DeviceManager(ctx:Context){
    val api=remember{Api(ctx)};val scope=rememberCoroutineScope()
    var email by remember{mutableStateOf("")};var pass by remember{mutableStateOf("")}
    var signed by remember{mutableStateOf(api.token!=null && api.uid!=null)}
    var target by remember{mutableStateOf(false)};var code by remember{mutableStateOf("")}
    var invite by remember{mutableStateOf("")};var msg by remember{mutableStateOf("")}
    var phones by remember{mutableStateOf(emptyList<Phone>())};var action by remember{mutableStateOf<Action?>(null)}
    var smsPhone by remember{mutableStateOf<Phone?>(null)};var number by remember{mutableStateOf("")};var body by remember{mutableStateOf("")}
    var appPhone by remember{mutableStateOf<Phone?>(null)}
    LaunchedEffect(signed,target,api.deviceId){
        if(signed && !target){while(true){try{phones=api.phones()}catch(e:Exception){msg=e.message?:"Refresh error"};delay(12000)}}
        if(signed && target && api.deviceId!=null){while(true){try{
            val i=Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val apps=ctx.packageManager.queryIntentActivities(i,0).map{it.activityInfo.packageName}.distinct().take(80)
            api.heartbeat(apps);if(action==null)action=api.pending()
        }catch(e:Exception){msg=e.message?:"Connection error"};delay(8000)}}
    }
    Scaffold(topBar={TopAppBar(title={Text("Farhan Device Manager")})}){pad->
        Column(Modifier.fillMaxSize().padding(pad).padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
            if(!signed){
                OutlinedTextField(email,{email=it},label={Text("Email")},modifier=Modifier.fillMaxWidth())
                OutlinedTextField(pass,{pass=it},label={Text("Password")},modifier=Modifier.fillMaxWidth())
                Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                    Button(onClick={scope.launch{try{api.auth(email,pass,false);signed=true;msg="Signed in"}catch(e:Exception){msg=e.message?:"Login failed"}}}){Text("Sign in")}
                    OutlinedButton(onClick={scope.launch{try{api.auth(email,pass,true);if(api.token!=null)signed=true;msg="Account created. Confirm email if required."}catch(e:Exception){msg=e.message?:"Sign up failed"}}}){Text("Sign up")}
                }
            }else{
                Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                    FilterChip(selected=!target,onClick={target=false},label={Text("Admin")})
                    FilterChip(selected=target,onClick={target=true},label={Text("Target Device")})
                    TextButton(onClick={api::signOut; signed=false}){Text("Sign out")}
                }
                if(!target){
                    Button(onClick={scope.launch{try{invite=api.invite();msg="Pairing code expires in 10 minutes"}catch(e:Exception){msg=e.message?:"Invite failed"}}}){Text("Create pairing code")}
                    if(invite.isNotBlank())Text("Pairing code: $invite",style=MaterialTheme.typography.headlineMedium)
                    Button(onClick={scope.launch{try{phones=api.phones();msg="Updated"}catch(e:Exception){msg=e.message?:"Refresh failed"}}}){Text("Refresh devices")}
                    LazyColumn(verticalArrangement=Arrangement.spacedBy(8.dp)){
                        items(phones){p->Card(Modifier.fillMaxWidth()){Column(Modifier.padding(12.dp)){
                            Text(p.name,style=MaterialTheme.typography.titleMedium);Text(p.model)
                            Text("Status: ${if(p.status=="online")"Online" else "Offline"}")
                            Row(horizontalArrangement=Arrangement.spacedBy(6.dp)){
                                OutlinedButton(onClick={scope.launch{try{api.send(p,"open_dialer");msg="Consent request sent"}catch(e:Exception){msg=e.message?:"Error"}}}){Text("Dialer")}
                                OutlinedButton(onClick={smsPhone=p;number="";body=""}){Text("SMS")}
                                OutlinedButton(onClick={appPhone=p}){Text("Open app")}
                            }
                            OutlinedButton(onClick={scope.launch{try{api.send(p,"disconnect");msg="Disconnect request sent"}catch(e:Exception){msg=e.message?:"Error"}}}){Text("Disconnect")}
                        }}}
                    }
                }else if(api.deviceId==null){
                    OutlinedTextField(code,{code=it.filter(Char::isDigit).take(6)},label={Text("6-digit code")})
                    Button(onClick={scope.launch{try{api.pair(code,ctx);msg="Paired"}catch(e:Exception){msg=e.message?:"Pairing failed"}}},enabled=code.length==6){Text("Pair this phone")}
                }else{
                    Text("Paired. Keep this screen open to receive consent requests.")
                    OutlinedButton(onClick={scope.launch{try{api.revoke();msg="Unpaired"}catch(e:Exception){msg=e.message?:"Error"}}}){Text("Unpair")}
                }
            }
            if(msg.isNotBlank())Text(msg)
        }
    }
    smsPhone?.let{p->AlertDialog(onDismissRequest={smsPhone=null},title={Text("Compose SMS")},text={Column{
        OutlinedTextField(number,{number=it},label={Text("Phone number")})
        OutlinedTextField(body,{body=it},label={Text("Message")})
        Text("Target phone owner must review and tap Send.")
    }},confirmButton={TextButton(onClick={scope.launch{try{api.send(p,"compose_sms",JSONObject().put("number",number).put("body",body));msg="Request sent"}catch(e:Exception){msg=e.message?:"Error"}};smsPhone=null}){Text("Send request")}},dismissButton={TextButton(onClick={smsPhone=null}){Text("Cancel")}})}
    appPhone?.let{p->AlertDialog(onDismissRequest={appPhone=null},title={Text("Choose app")},text={LazyColumn(Modifier.heightIn(max=350.dp)){items(p.apps){pkg->TextButton(onClick={scope.launch{try{api.send(p,"open_app",JSONObject().put("package",pkg));msg="Request sent"}catch(e:Exception){msg=e.message?:"Error"}};appPhone=null}){Text(pkg)}}}},confirmButton={TextButton(onClick={appPhone=null}){Text("Close")}})}
    action?.let{a->AlertDialog(onDismissRequest={},title={Text("Allow remote action?")},text={Text(when(a.type){
        "open_dialer"->"Admin wants to open your dialer. No call will be placed."
        "compose_sms"->"Admin wants to open SMS composer. You review and tap Send."
        "open_app"->"Admin wants to open ${a.payload.optString("package")}."
        "disconnect"->"Admin wants to disconnect this device."
        else->"Requested action: ${a.type}"
    })},confirmButton={TextButton(onClick={scope.launch{try{
        api.respond(a,true)
        when(a.type){
            "open_dialer"->ctx.startActivity(Intent(Intent.ACTION_DIAL,Uri.parse("tel:${Uri.encode(a.payload.optString("number"))}")))
            "compose_sms"->ctx.startActivity(Intent(Intent.ACTION_SENDTO,Uri.parse("smsto:${Uri.encode(a.payload.optString("number"))}")).putExtra("sms_body",a.payload.optString("body")))
            "open_app"->{val launch=ctx.packageManager.getLaunchIntentForPackage(a.payload.optString("package"));if(launch!=null)ctx.startActivity(launch)}
            "disconnect"->api.revoke()
        }
        api.complete(a)
    }catch(e:Exception){msg=e.message?:"Action failed"};action=null}}){Text("Allow")}},dismissButton={TextButton(onClick={scope.launch{try{api.respond(a,false)}catch(_:Exception){};action=null}}){Text("Deny")}})}
}
