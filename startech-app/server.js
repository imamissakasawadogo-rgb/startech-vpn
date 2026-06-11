'use strict';

var express=require('express'),jwt=require('jsonwebtoken'),bcrypt=require('bcryptjs'),cors=require('cors'),path=require('path'),fs=require('fs'),nacl=require('tweetnacl');
var app=express(),PORT=3002,SECRET='STARTECH_APP_2026',DATA=path.join(__dirname,'data','db.json');
app.use(cors());app.use(express.json());app.use(express.static(path.join(__dirname,'public')));

// CONFIG SERVEUR WG
var WG_SERVER_IP='194.163.174.142';
var WG_SERVER_PORT=51820;
var WG_SERVER_PUBKEY='TGuhgHXe/ty2QjNfbP1vyp6NFoEgqhGU/x3WYTVfCSQ=';
var WG_SUBNET='10.8.0';
var CRT_PRICE=50;
var PLANS=[
  {id:'wg',name:'WireGuard VPN',desc:'Tunnel WireGuard pour routeur MikroTik',cost:10,icon:'🔒'},
  {id:'mikhmon',name:'Mikhmon Online',desc:'Gestion hotspot MikroTik en ligne',cost:10,icon:'📡'},
  {id:'vpn',name:'Compte VPN',desc:'Acces VPN dedie Startech',cost:10,icon:'👤'}
];
var PACKS=[
  {id:'p20',crt:20,fcfa:1000},
  {id:'p50',crt:50,fcfa:2500},
  {id:'p100',crt:100,fcfa:5000},
  {id:'p200',crt:200,fcfa:10000}
];

// GÉNÉRATION CLÉS WIREGUARD
function genWGKeys(){
  var priv=nacl.randomBytes(32);
  priv[0]&=248;priv[31]&=127;priv[31]|=64;
  var pub=nacl.scalarMult.base(priv);
  return{privateKey:Buffer.from(priv).toString('base64'),publicKey:Buffer.from(pub).toString('base64')};
}

// ATTRIBUER IP CLIENT
function assignClientIP(d){
  var used=[];
  if(d.services){d.services.forEach(function(s){if(s.wgIP)used.push(parseInt(s.wgIP.split('.')[3]));});}
  for(var i=2;i<=254;i++){if(used.indexOf(i)===-1)return WG_SUBNET+'.'+i;}
  return null;
}

// GÉNÉRER TOKEN D'INSTALLATION
function genInstallToken(){
  var chars='ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  var token='';
  var bytes=nacl.randomBytes(32);
  for(var i=0;i<32;i++){token+=chars[bytes[i]%chars.length];}
  return token;
}

// GÉNÉRER SCRIPT ROUTEROS WIREGUARD
function genRouterOSScript(clientName,clientPrivKey,clientIP,serverPubKey,serverIP,serverPort){
  var iface='startech-vpn';
  return '/interface wireguard\n'+
    'add listen-port=13231 mtu=1420 name='+iface+' private-key="'+clientPrivKey+'"\n\n'+
    '/interface wireguard peers\n'+
    'add allowed-address=0.0.0.0/0 endpoint-address='+serverIP+' endpoint-port='+serverPort+' \\\n'+
    '    interface='+iface+' name=startech-peer \\\n'+
    '    public-key="'+serverPubKey+'"\n\n'+
    '/ip address\n'+
    'add address='+clientIP+'/24 interface='+iface+' network='+WG_SUBNET+'.0\n\n'+
    '/ip route\n'+
    'add dst-address='+WG_SUBNET+'.0/24 gateway='+iface+'\n\n'+
    '# Startech BUSINESS - VPN WireGuard\n'+
    '# Client: '+clientName+'\n'+
    '# IP: '+clientIP+'\n'+
    '# Serveur: '+serverIP+':'+serverPort;
}

function db(){
  if(!fs.existsSync(DATA)){
    fs.mkdirSync(path.dirname(DATA),{recursive:true});
    var d={users:[{id:'u1',username:'admin',email:'admin@startech.com',password:bcrypt.hashSync('STARTECH2026',10),role:'admin',credits:100,gnx:50,createdAt:new Date().toISOString()}],routers:[],vpn_networks:[],vpn_accounts:[],scripts:[],transactions:[],services:[],payments:[]};
    fs.writeFileSync(DATA,JSON.stringify(d,null,2));return d;
  }
  return JSON.parse(fs.readFileSync(DATA,'utf8'));
}
function save(d){fs.writeFileSync(DATA,JSON.stringify(d,null,2));}
function auth(req,res,next){var h=req.headers['authorization'];if(!h)return res.status(401).json({error:'Token manquant'});try{req.user=jwt.verify(h.split(' ')[1],SECRET);next();}catch(e){res.status(401).json({error:'Token invalide'});}}
function admin(req,res,next){if(req.user.role!=='admin')return res.status(403).json({error:'Acces refuse'});next();}

// PROFIL UTILISATEUR
app.get('/api/profile',auth,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  if(!u)return res.status(404).json({error:'Introuvable'});
  res.json({id:u.id,username:u.username,email:u.email,phone:u.phone||'',name:u.name||u.username,role:u.role,credits:u.credits,gnx:u.gnx,createdAt:u.createdAt});
});

app.put('/api/profile',auth,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  if(!u)return res.status(404).json({error:'Introuvable'});
  if(req.body.name)u.name=req.body.name;
  if(req.body.phone)u.phone=req.body.phone;
  if(req.body.password&&req.body.oldPassword){
    if(!require('bcryptjs').compareSync(req.body.oldPassword,u.password))return res.status(400).json({error:'Ancien mot de passe incorrect'});
    u.password=require('bcryptjs').hashSync(req.body.password,10);
  }
  save(d);res.json({success:true,message:'Profil mis à jour'});
});

// RENOUVELER UN SERVICE
app.post('/api/services/:id/renew',auth,function(req,res){
  var d=db();
  var svc=d.services?d.services.find(function(s){return s.id===req.params.id&&s.userId===req.user.id;}):null;
  if(!svc)return res.status(404).json({error:'Service introuvable'});
  var u=d.users.find(function(x){return x.id===req.user.id;});
  if(!u)return res.status(404).json({error:'Utilisateur introuvable'});
  var months=parseInt(req.body.months)||1;
  var cost=10*months;
  // Si expiré depuis plus d'1 mois, +5 CRT de réactivation
  var exp=new Date(svc.expiry);
  var oneMonthAgo=new Date();oneMonthAgo.setMonth(oneMonthAgo.getMonth()-1);
  var reactiv=exp<oneMonthAgo?5:0;
  var total=cost+reactiv;
  if(u.credits<total)return res.status(400).json({error:'Credits insuffisants. Besoin: '+total+' CRT'});
  u.credits-=total;
  // Prolonger depuis aujourd'hui ou depuis expiration si pas encore expiré
  var base=exp>new Date()?exp:new Date();
  base.setMonth(base.getMonth()+months);
  svc.expiry=base.toISOString();
  svc.status='active';
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'renouvellement',amount:-total,note:svc.planName+' x'+months+'mois'+(reactiv?' +reactiv':''),date:new Date().toISOString()});
  save(d);
  res.json({success:true,newExpiry:svc.expiry,creditsLeft:u.credits});
});

// MOT DE PASSE OUBLIÉ (sans email pour l'instant - version simple)
app.post('/api/auth/forgot',function(req,res){
  var email=req.body.email;
  if(!email)return res.status(400).json({error:'Email requis'});
  var d=db();
  var u=d.users.find(function(x){return x.email===email;});
  // Ne pas révéler si l'email existe ou non (sécurité)
  if(!u)return res.json({message:'Si cet email existe, un lien de réinitialisation a été envoyé'});
  // Générer token reset
  var token=require('crypto').randomBytes(32).toString('hex');
  u.resetToken=token;
  u.resetExpiry=new Date(Date.now()+3600000).toISOString(); // 1h
  save(d);
  // TODO: Envoyer email avec le lien
  var resetLink='https://app.startech-pro.com/reset?token='+token;
  console.log('Reset link for '+email+': '+resetLink);
  res.json({message:'Lien de réinitialisation envoyé à '+email+'\n(Vérifiez WhatsApp ou contactez le support)'});
});

app.post('/api/auth/reset',function(req,res){
  var token=req.body.token,password=req.body.password;
  if(!token||!password)return res.status(400).json({error:'Token et mot de passe requis'});
  var d=db();
  var u=d.users.find(function(x){return x.resetToken===token;});
  if(!u)return res.status(400).json({error:'Token invalide ou expiré'});
  if(new Date(u.resetExpiry)<new Date())return res.status(400).json({error:'Token expiré'});
  u.password=require('bcryptjs').hashSync(password,10);
  u.resetToken=null;u.resetExpiry=null;
  save(d);
  res.json({success:true,message:'Mot de passe réinitialisé avec succès'});
});

// GOOGLE AUTH
app.post('/api/auth/google',function(req,res){
  var credential=req.body.credential;
  if(!credential)return res.status(400).json({error:'Token Google manquant'});
  try{
    // Décoder le JWT Google (sans vérification de signature pour simplifier)
    var payload=JSON.parse(Buffer.from(credential.split('.')[1],'base64').toString());
    var email=payload.email;
    var name=payload.name||email.split('@')[0];
    var googleId=payload.sub;
    if(!email)return res.status(400).json({error:'Email Google non disponible'});
    var d=db();
    // Chercher utilisateur existant par email ou googleId
    var u=d.users.find(function(x){return x.email===email||x.googleId===googleId;});
    if(!u){
      // Créer nouveau compte automatiquement
      var username=name.replace(/\s+/g,'_').toLowerCase()+Math.floor(Math.random()*100);
      // S'assurer que le username est unique
      while(d.users.find(function(x){return x.username===username;})){
        username=name.replace(/\s+/g,'_').toLowerCase()+Math.floor(Math.random()*1000);
      }
      u={id:'u'+Date.now(),username:username,email:email,googleId:googleId,name:name,password:'',role:'client',credits:0,gnx:0,createdAt:new Date().toISOString()};
      d.users.push(u);save(d);
    } else if(!u.googleId){
      // Lier le compte Google existant
      u.googleId=googleId;
      if(!u.name)u.name=name;
      save(d);
    }
    var t=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:'24h'});
    res.json({token:t,user:{id:u.id,username:u.username,email:u.email,name:u.name,role:u.role,credits:u.credits,gnx:u.gnx}});
  }catch(e){
    res.status(400).json({error:'Token Google invalide'});
  }
});

// AUTH
app.post('/api/auth/login',function(req,res){
  var d=db(),u=d.users.find(function(x){return x.username===req.body.username||x.email===req.body.username;});
  if(!u||!bcrypt.compareSync(req.body.password,u.password))return res.status(401).json({error:'Identifiants incorrects'});
  var t=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:'24h'});
  res.json({token:t,user:{id:u.id,username:u.username,email:u.email,role:u.role,credits:u.credits,gnx:u.gnx}});
});

app.post('/api/auth/register',function(req,res){
  var d=db();
  if(!req.body.username||!req.body.password||!req.body.email)return res.status(400).json({error:'Champs requis manquants'});
  if(d.users.find(function(x){return x.username===req.body.username;}))return res.status(400).json({error:'Nom utilisateur deja pris'});
  if(d.users.find(function(x){return x.email===req.body.email;}))return res.status(400).json({error:'Email deja utilise'});
  var u={id:'u'+Date.now(),username:req.body.username,email:req.body.email,password:bcrypt.hashSync(req.body.password,10),role:'client',credits:0,gnx:0,createdAt:new Date().toISOString()};
  d.users.push(u);save(d);
  var t=jwt.sign({id:u.id,username:u.username,role:u.role},SECRET,{expiresIn:'24h'});
  res.json({token:t,user:{id:u.id,username:u.username,email:u.email,role:u.role,credits:0,gnx:0}});
});

app.post('/api/auth/register-admin',auth,admin,function(req,res){
  var d=db();
  if(d.users.find(function(x){return x.username===req.body.username;}))return res.status(400).json({error:'Existant'});
  var u={id:'u'+Date.now(),username:req.body.username,email:req.body.email||'',password:bcrypt.hashSync(req.body.password,10),role:req.body.role||'client',credits:0,gnx:0,createdAt:new Date().toISOString()};
  d.users.push(u);save(d);
  res.json({success:true,user:{id:u.id,username:u.username,role:u.role}});
});

// DASHBOARD
app.get('/api/dashboard',auth,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  var myServices=d.services?d.services.filter(function(s){return s.userId===req.user.id;}):[]; 
  res.json({stats:{routers:d.routers.length,vpn_networks:d.vpn_networks.length,vpn_accounts:d.vpn_accounts.length,scripts:d.scripts.length,users:d.users.length,transactions:d.transactions.length,services:d.services?d.services.length:0},user:{credits:u?u.credits:0,gnx:u?u.gnx:0},myServices:myServices});
});

app.get('/api/plans',function(req,res){res.json(PLANS);});
app.get('/api/packs',function(req,res){res.json(PACKS);});

// ACHETER SERVICE + GÉNÉRATION SCRIPT
app.post('/api/services/buy',auth,function(req,res){
  var d=db();
  var u=d.users.find(function(x){return x.id===req.user.id;});
  if(!u)return res.status(404).json({error:'Utilisateur introuvable'});
  var plan=PLANS.find(function(p){return p.id===req.body.planId;});
  if(!plan)return res.status(400).json({error:'Plan introuvable'});
  var months=parseInt(req.body.months)||1;
  var cost=plan.cost*months;
  if(u.credits<cost)return res.status(400).json({error:'Credits insuffisants. Vous avez '+u.credits+' CRT, il faut '+cost+' CRT'});
  u.credits-=cost;
  var expiry=new Date();expiry.setMonth(expiry.getMonth()+months);
  if(!d.services)d.services=[];
  var installToken=genInstallToken();
  var svc={id:'svc'+Date.now(),userId:u.id,planId:plan.id,planName:plan.name,months:months,cost:cost,status:'active',expiry:expiry.toISOString(),createdAt:new Date().toISOString(),installToken:installToken,details:{}};
  // Générer script selon le plan
  if(plan.id==='wg'){
    var keys=genWGKeys();
    var clientIP=assignClientIP(d);
    svc.wgIP=clientIP;
    svc.details={
      privateKey:keys.privateKey,
      publicKey:keys.publicKey,
      clientIP:clientIP,
      serverPubKey:WG_SERVER_PUBKEY,
      serverIP:WG_SERVER_IP,
      serverPort:WG_SERVER_PORT,
      script:genRouterOSScript(u.username,keys.privateKey,clientIP,WG_SERVER_PUBKEY,WG_SERVER_IP,WG_SERVER_PORT)
    };
  } else if(plan.id==='mikhmon'){
    svc.details={
      mikhmonURL:'https://baobab.mikhmonv1.com',
      username:u.username,
      password:'STB'+Math.random().toString(36).substr(2,8).toUpperCase(),
      note:'Accedez a votre tableau Mikhmon avec ces identifiants'
    };
  } else if(plan.id==='vpn'){
    var vkeys=genWGKeys();
    var vIP=assignClientIP(d);
    svc.wgIP=vIP;
    svc.details={
      type:'WireGuard',
      privateKey:vkeys.privateKey,
      publicKey:vkeys.publicKey,
      clientIP:vIP,
      serverPubKey:WG_SERVER_PUBKEY,
      serverIP:WG_SERVER_IP,
      serverPort:WG_SERVER_PORT,
      script:genRouterOSScript(u.username,vkeys.privateKey,vIP,WG_SERVER_PUBKEY,WG_SERVER_IP,WG_SERVER_PORT)
    };
  }
  d.services.push(svc);
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'achat_service',amount:-cost,note:plan.name+' x'+months+'mois',date:new Date().toISOString()});
  save(d);
  res.json({success:true,service:svc,creditsLeft:u.credits});
});

app.get('/api/services/mine',auth,function(req,res){
  var d=db();
  res.json(d.services?d.services.filter(function(s){return s.userId===req.user.id;}):[]);
});

app.get('/api/services',auth,admin,function(req,res){
  var d=db();res.json(d.services||[]);
});

// SCRIPT D'UN SERVICE (API authentifiée)
app.get('/api/services/:id/script',auth,function(req,res){
  var d=db();
  var svc=d.services?d.services.find(function(s){return s.id===req.params.id&&(s.userId===req.user.id||req.user.role==='admin')}):null;
  if(!svc)return res.status(404).json({error:'Service introuvable'});
  if(!svc.details||!svc.details.script)return res.status(400).json({error:'Pas de script pour ce service'});
  // Générer token si absent
  if(!svc.installToken){
    svc.installToken=genInstallToken();
    save(d);
  }
  res.json({
    script:svc.details.script,
    clientIP:svc.details.clientIP,
    serverIP:svc.details.serverIP,
    serverPort:svc.details.serverPort,
    installToken:svc.installToken,
    installCmd:'/tool fetch url="https://api.startech-pro.com/install/'+svc.installToken+'" mode=https dst-path=mkrt;/import mkrt;'
  });
});

// ROUTE PUBLIQUE - Routeur MikroTik télécharge le script via token
app.get('/install/:token',function(req,res){
  var d=db();
  if(!d.services)return res.status(404).send('# Token invalide');
  var svc=d.services.find(function(s){return s.installToken===req.params.token;});
  if(!svc)return res.status(404).send('# Token invalide ou expire');
  var exp=new Date(svc.expiry);
  if(exp<new Date())return res.status(403).send('# Service expire le '+exp.toLocaleDateString('fr-FR'));
  if(!svc.details||!svc.details.script)return res.status(404).send('# Pas de script disponible');
  // Enregistrer la date de dernière installation
  svc.lastInstall=new Date().toISOString();
  save(d);
  res.setHeader('Content-Type','text/plain');
  res.send(svc.details.script);
});

// CRÉDITS
app.post('/api/users/:id/credits',auth,admin,function(req,res){
  var d=db(),u=d.users.find(function(x){return x.id===req.params.id;});
  if(!u)return res.status(404).json({error:'Introuvable'});
  u.credits+=parseInt(req.body.amount)||0;
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'recharge',amount:parseInt(req.body.amount)||0,note:req.body.note||'Recharge admin',date:new Date().toISOString()});
  save(d);res.json({success:true,credits:u.credits});
});

// PAIEMENT
app.post('/api/payment/init',auth,function(req,res){
  var pack=PACKS.find(function(p){return p.id===req.body.packId;});
  if(!pack)return res.status(400).json({error:'Pack introuvable'});
  var d=db(),u=d.users.find(function(x){return x.id===req.user.id;});
  var payment={id:'pay'+Date.now(),userId:u.id,username:u.username,packId:pack.id,crt:pack.crt,fcfa:pack.fcfa,status:'pending',createdAt:new Date().toISOString()};
  if(!d.payments)d.payments=[];
  d.payments.push(payment);save(d);
  res.json({paymentId:payment.id,amount:pack.fcfa,crt:pack.crt});
});

app.post('/api/payment/confirm/:id',auth,admin,function(req,res){
  var d=db();
  if(!d.payments)return res.status(404).json({error:'Aucun paiement'});
  var pay=d.payments.find(function(p){return p.id===req.params.id;});
  if(!pay)return res.status(404).json({error:'Introuvable'});
  if(pay.status==='confirmed')return res.status(400).json({error:'Deja confirme'});
  var u=d.users.find(function(x){return x.id===pay.userId;});
  if(!u)return res.status(404).json({error:'Utilisateur introuvable'});
  pay.status='confirmed';u.credits+=pay.crt;
  d.transactions.push({id:'t'+Date.now(),userId:u.id,type:'recharge',amount:pay.crt,note:'Paiement '+pay.fcfa+' FCFA',date:new Date().toISOString()});
  save(d);res.json({success:true,credits:u.credits});
});

app.get('/api/payments',auth,admin,function(req,res){var d=db();res.json(d.payments||[]);});

// PORTS - assigner ports tunnelisés à un service
var PORT_BASE=9000; // ports clients commencent à 9000
function assignPorts(d,svcId){
  // Chaque client a 3 ports: winbox, webfig, api
  var usedBases=[];
  if(d.services){
    d.services.forEach(function(s){
      if(s.ports&&s.ports.base)usedBases.push(s.ports.base);
    });
  }
  var base=PORT_BASE;
  while(usedBases.indexOf(base)!==-1)base+=3;
  return{
    base:base,
    winbox:{port:base,service:'Winbox',proto:'TCP',local:8291},
    webfig:{port:base+1,service:'WebFig',proto:'TCP',local:80},
    api:{port:base+2,service:'API-Mikhmon',proto:'TCP',local:8728}
  };
}

// OBTENIR PORTS D'UN SERVICE
app.get('/api/services/:id/ports',auth,function(req,res){
  var d=db();
  var svc=d.services?d.services.find(function(s){
    return s.id===req.params.id&&(s.userId===req.user.id||req.user.role==='admin');
  }):null;
  if(!svc)return res.status(404).json({error:'Service introuvable'});
  if(!svc.ports){
    // Assigner les ports si pas encore fait
    svc.ports=assignPorts(d,svc.id);
    save(d);
  }
  var host='api.startech-pro.com';
  res.json({
    ports:svc.ports,
    host:host,
    clientIP:svc.details?svc.details.clientIP:'N/A',
    addresses:[
      {label:'Winbox',address:host+':'+svc.ports.winbox.port,icon:'🖥️',copy:host+':'+svc.ports.winbox.port},
      {label:'WebFig',address:host+':'+svc.ports.webfig.port,icon:'🌐',copy:'http://'+host+':'+svc.ports.webfig.port},
      {label:'API-Mikhmon',address:host+':'+svc.ports.api.port,icon:'📡',copy:host+':'+svc.ports.api.port}
    ],
    iptablesScript:
      '# Redirection ports pour client IP '+( svc.details?svc.details.clientIP:'X.X.X.X')+'\n'+
      'iptables -t nat -A PREROUTING -p tcp --dport '+svc.ports.winbox.port+' -j DNAT --to-destination '+(svc.details?svc.details.clientIP:'X.X.X.X')+':8291\n'+
      'iptables -t nat -A PREROUTING -p tcp --dport '+svc.ports.webfig.port+' -j DNAT --to-destination '+(svc.details?svc.details.clientIP:'X.X.X.X')+':80\n'+
      'iptables -t nat -A PREROUTING -p tcp --dport '+svc.ports.api.port+' -j DNAT --to-destination '+(svc.details?svc.details.clientIP:'X.X.X.X')+':8728\n'+
      'iptables -t nat -A POSTROUTING -j MASQUERADE'
  });
});

// USERS
app.get('/api/users',auth,admin,function(req,res){
  var d=db();
  res.json(d.users.map(function(u){return{id:u.id,username:u.username,email:u.email,role:u.role,credits:u.credits,gnx:u.gnx,createdAt:u.createdAt};}));
});

// TRANSACTIONS
app.get('/api/transactions',auth,function(req,res){
  var d=db(),t=req.user.role==='admin'?d.transactions:d.transactions.filter(function(x){return x.userId===req.user.id;});
  res.json(t);
});

// ROUTERS
app.get('/api/routers',auth,function(req,res){res.json(db().routers);});
app.post('/api/routers',auth,function(req,res){
  var d=db(),r={id:'r'+Date.now(),name:req.body.name,ip:req.body.ip,port:req.body.port||8728,username:req.body.username||'admin',password:req.body.password||'',ownerId:req.user.id,expiry:req.body.expiry||null,createdAt:new Date().toISOString()};
  d.routers.push(r);save(d);res.json(r);
});
app.delete('/api/routers/:id',auth,function(req,res){
  var d=db();d.routers=d.routers.filter(function(r){return r.id!==req.params.id;});save(d);res.json({success:true});
});

// WG NETWORKS
app.get('/api/wg/networks',auth,function(req,res){res.json(db().vpn_networks);});
app.post('/api/wg/networks',auth,function(req,res){
  var d=db(),n={id:'wg'+Date.now(),name:req.body.name,subnet:req.body.subnet||'10.8.0.0/24',port:req.body.port||51820,ownerId:req.user.id,devices:[],createdAt:new Date().toISOString()};
  d.vpn_networks.push(n);save(d);res.json(n);
});

// VPN ACCOUNTS
app.get('/api/vpn/accounts',auth,function(req,res){
  var d=db(),a=req.user.role==='admin'?d.vpn_accounts:d.vpn_accounts.filter(function(x){return x.ownerId===req.user.id;});
  res.json(a);
});
app.post('/api/vpn/accounts',auth,function(req,res){
  var d=db(),a={id:'vpn'+Date.now(),username:req.body.username,plan:req.body.plan||'1mois',price:req.body.price||500,expiry:req.body.expiry,ownerId:req.user.id,status:'active',createdAt:new Date().toISOString()};
  d.vpn_accounts.push(a);save(d);res.json(a);
});

// SCRIPTS
app.get('/api/scripts',auth,function(req,res){res.json(db().scripts);});
app.post('/api/scripts',auth,admin,function(req,res){
  var d=db(),s={id:'s'+Date.now(),name:req.body.name,description:req.body.description||'',category:req.body.category||'general',code:req.body.code||'',cost:req.body.cost||0,createdAt:new Date().toISOString()};
  d.scripts.push(s);save(d);res.json(s);
});

app.get('/{*path}',function(req,res){res.sendFile(path.join(__dirname,'public','index.html'));});
app.listen(PORT,function(){console.log('Startech App v3 port '+PORT);});
