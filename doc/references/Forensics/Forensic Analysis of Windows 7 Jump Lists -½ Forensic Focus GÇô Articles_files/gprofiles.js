// http://javascriptcompressor.com/
if('undefined'==typeof(console)){console={"log":function(str){},"debug":function(str){}}}var Gravatar={"profile_stack":{},"profile_map":{},"overTimeout":false,"outTimeout":false,"stopOver":false,"active_grav":false,"active_hash":false,"active_id":false,"active_grav_clone":false,"profile_cb":null,"stats_queue":[],"throbber":null,"has_bg":false,"disabled":false,"url_prefix":'http://en',"disable":function(){Gravatar.disabled=true;Gravatar.hide_card();var d=new Date(2100,1,1,1,1,1);Gravatar.stat('disable');if(-1==window.location.host.search(/wordpress.com/i)){document.cookie='nohovercard=1; expires='+d.toUTCString()+';'}else{document.cookie='nohovercard=1; expires='+d.toUTCString()+'; domain=.wordpress.com; path=/'}},"mouseOut":function(e){e.stopImmediatePropagation();Gravatar.stopOver=true;Gravatar.outTimeout=setTimeout(function(){Gravatar.hide_card()},300)},"init":function(container,noGrav){var ca=document.cookie.split(';'),i,c;for(i=0;i<ca.length;i++){c=ca[i];while(' '==c.charAt(0)){c=c.substring(1,c.length)}if(0==c.indexOf('nohovercard=1')){return}}if('https:'==window.location.protocol)this.url_prefix='https://secure';this.attach_profiles(container,noGrav);this.add_card_css();jQuery('img.grav-hashed').live('mouseenter.gravatar mouseleave.gravatar',function(e){if(Gravatar.disabled){return}e.preventDefault();e.stopPropagation();if('mouseleave'==e.type||'mouseout'==e.type){return Gravatar.mouseOut.call(this,e)}Gravatar.stopOver=false;Gravatar.active_id=jQuery(this).attr('id');Gravatar.active_hash=Gravatar.active_id.split('-')[1];Gravatar.untilt_gravatar();clearTimeout(Gravatar.overTimeout);if(false===Gravatar.profile_map['g'+Gravatar.active_hash]){return}Gravatar.stat('hover');clearTimeout(Gravatar.outTimeout);Gravatar.tilt_gravatar();Gravatar.fetch_profile_by_hash(Gravatar.active_hash,Gravatar.active_id);Gravatar.overTimeout=setTimeout(function(){Gravatar.show_card()},600)});jQuery('div.gcard, img.grav-clone').live('mouseenter.gravatar mouseleave.gravatar',function(e){if(Gravatar.disabled){return}e.preventDefault();e.stopPropagation();if(e.type=='mouseenter'||e.type=='mouseover'){Gravatar.stopOver=false;clearTimeout(Gravatar.outTimeout)}else{Gravatar.mouseOut.call(this,e)}});jQuery(window).bind('scroll',function(){if(!Gravatar.active_hash.length){return}Gravatar.hide_card()})},"attach_profiles":function(container,noGrav){setInterval(Gravatar.send_stats,3000);container="undefined"==typeof(container)?"body":container;if(noGrav&&'string'==typeof(noGrav)){jQuery(noGrav).addClass('no-grav')}jQuery(container+' img[src*="gravatar.com/avatar"]').not('.no-grav, .no-grav img').each(function(){hash=Gravatar.extract_hash(this);uniq=0;if(jQuery('#grav-'+hash+'-'+uniq).length){while(jQuery('#grav-'+hash+'-'+uniq).length){uniq++}}var g=jQuery(this).attr('id','grav-'+hash+'-'+uniq).attr('title','').removeAttr('title');if(g.parent('a').size()){g.parent('a').attr('title','').removeAttr('title')}g.addClass('grav-hashed');if(g.parents('#comments, .comments, #commentlist, .commentlist, .grav-hijack').size()||!g.parents('a:first').size()){g.addClass('grav-hijack')}})},"show_card":function(){if(Gravatar.stopOver){return}dom_id=this.profile_map['g'+Gravatar.active_hash];jQuery('.gcard').hide();if('fetching'==this.profile_stack['g'+Gravatar.active_hash]){Gravatar.show_throbber();this.listen(Gravatar.active_hash,'show_card');Gravatar.stat('wait');return}if('undefined'==typeof(this.profile_stack['g'+Gravatar.active_hash])){Gravatar.show_throbber();this.listen(Gravatar.active_hash,'show_card');this.fetch_profile_by_hash(Gravatar.active_hash,dom_id);return}Gravatar.stat('show');Gravatar.hide_throbber();if(!jQuery('#profile-'+this.active_hash).length){this.build_card(this.active_hash,this.profile_stack['g'+this.active_hash])}this.render_card(this.active_grav,'profile-'+this.active_hash)},"hide_card":function(){clearTimeout(Gravatar.overTimeout);this.untilt_gravatar();jQuery('div.gcard').filter('#profile-'+this.active_hash).fadeOut(120,function(){jQuery('img.grav-large').stop().remove()}).end().not('#profile-'+this.active_hash).hide()},"render_card":function(grav,card_id){var card_el=jQuery('#'+card_id).stop();var grav_el=grav;var grav_pos=grav_el.offset();if(null!=grav_pos){var grav_width=grav_el.width();var grav_height=grav_el.height();var grav_space=5+(grav_width*.4);var card_width=card_el.width();var card_height=card_el.height();if(card_width==jQuery(window).width()){card_width=400;card_height=200}var left=grav_pos.left-17;var top=grav_pos.top-7;var grav_pos_class='pos-right';if(grav_pos.left+grav_width+grav_space+card_width>jQuery(window).width()+jQuery(window).scrollLeft()){left=grav_pos.left-card_width+grav_width+17;grav_pos_class='pos-left'}var top_offset=grav_height*.25;jQuery('#'+card_id).removeClass('pos-right pos-left').addClass(grav_pos_class).css({'top':(top-top_offset)+'px','left':left+'px'});var arrow_offset=(grav_height/2);if(arrow_offset>card_height){arrow_offset=card_height/2}if(arrow_offset>(card_height/2)-6){arrow_offset=(card_height/2)-6}if(arrow_offset>53){arrow_offset=53}if(this.has_bg){arrow_offset=arrow_offset-8}if(arrow_offset<0){arrow_offset=0}var css={'height':((grav_height*2)+top_offset)+'px'};if('pos-right'==grav_pos_class){css['right']='auto';css['left']='-7px';css['background-position']='0px '+arrow_offset+'px'}else{css['right']='-10px';css['left']='auto';css['background-position']='0px '+arrow_offset+'px'}jQuery('#'+card_id+' .grav-cardarrow').css(css)}card_el.stop().css({opacity:0}).show().animate({opacity:1},150,'linear',function(){jQuery(this).css({opacity:'auto'});jQuery(this).stop();var date=new Date();var qp='http';if('https:'==window.location.protocol){qp+='s'}var url=qp+'://pixel.quantserve.com/pixel/p-18-mFEk4J448M.gif?labels=type.gravatar.hovercard&rand='+Math.random().toString()+'-'+date.getTime();var img=new Image(1,1);img.src=url})},"build_card":function(hash,profile){Object.size=function(obj){var size=0,key;for(key in obj){if(obj.hasOwnProperty(key)){size++}}return size};GProfile.init(profile);var urls=GProfile.get('urls');var photos=GProfile.get('photos');var services=GProfile.get('accounts');var limit=100;if(Object.size(urls)>3){limit+=90}else{limit+=10+(20*Object.size(urls))}if(Object.size(services)>0){limit+=30}var description=GProfile.get('aboutMe');description=description.replace(/<[^>]+>/ig,'');description=description.toString().substr(0,limit);if(limit==description.length){description+='<a href="'+GProfile.get('profileUrl')+'" target="_blank">&#8230;</a>'}var card_class='grav-inner';if(Gravatar.my_hash&&hash==Gravatar.my_hash){card_class+=' grav-is-user';if(!description.length){description="<p>Want a better profile? <a class='grav-edit-profile' href='http://gravatar.com/profiles/edit/?noclose' target='_blank'>Click here</a>.</p>"}}if(description.length){card_class+=' gcard-about'}name=GProfile.get('displayName');if(!name.length){name=GProfile.get('preferredUsername')}var card='<div id="profile-'+hash+'" class="gcard grofile"> 						<div class="grav-inner"> 							<div class="grav-grav"> 								<a href="'+GProfile.get('profileUrl')+'" target="_blank"> 									<img src="'+GProfile.get('thumbnailUrl')+'?s=100&r=pg&d=mm" width="100" height="100" /> 								</a> 							</div> 							<div class="grav-info"> 								<h4><a href="'+GProfile.get('profileUrl')+'" target="_blank">'+name+'</a></h4> 								<p class="grav-loc">'+GProfile.get('currentLocation')+'</p> 								<p class="grav-about">'+description+'</p> 								<div class="grav-view-complete-button"> 									<a href="'+GProfile.get('profileUrl')+'" target="_blank" class="grav-view-complete">View Complete Profile</a> 								</div> 								<p class="grav-disable"><a href="#" onclick="Gravatar.disable(); return false">Turn off hovercards</a></p> 							</div> 							<div style="clear:both"></div> 						</div> 						<div class="grav-cardarrow"></div> 						<div class="grav-tag"><a href="http://gravatar.com/" title="Powered by Gravatar.com" target="_blank">&nbsp;</a></div> 					</div>';jQuery('body').append(jQuery(card));jQuery('#profile-'+hash+' .grav-inner').addClass(card_class);this.has_bg=false;var bg=GProfile.get('profileBackground');if(Object.size(bg)){this.has_bg=true;var bg_css={padding:'8px 0'};if(bg.color){bg_css['background-color']=bg.color}if(bg.url){bg_css['background-image']='url('+bg.url+')'}if(bg.position){bg_css['background-position']=bg.position}if(bg.repeat){bg_css['background-repeat']=bg.repeat}jQuery('#profile-'+hash).css(bg_css);jQuery('#profile-'+hash+' .grav-tag').css('top','8px')}if(!jQuery('#profile-'+hash+' .gcard-links').length&&!jQuery('#profile-'+hash+' .gcard-services').length){jQuery('#profile-'+hash+' .grav-rightcol').css({'width':'auto'})}if(!jQuery('#profile-'+hash+' .gcard-about').length){jQuery('#profile-'+hash+' .grav-leftcol').css({'width':'auto'})}if(jQuery.isFunction(Gravatar.profile_cb)){Gravatar.loaded_js(hash,'profile-'+hash)}jQuery('#profile-'+hash+' a.grav-extra-comments').click(function(e){return Gravatar.stat('click_comment',e)});jQuery('#profile-'+hash+' a.grav-extra-likes').click(function(e){return Gravatar.stat('click_like',e)});jQuery('#profile-'+hash+' .grav-links a').click(function(e){return Gravatar.stat('click_link',e)});jQuery('#profile-'+hash+' .grav-services a').click(function(e){return Gravatar.stat('click_service',e)});jQuery('#profile-'+hash+' h4 a, #profile-'+hash+' .grav-view-complete, #profile-'+hash+' .grav-grav a').click(function(e){return Gravatar.stat('to_profile',e)});jQuery('#profile-'+hash+' .grav-tag a').click(function(e){if(3==e.which||2==e.button||e.altKey||e.metaKey||e.ctrlKey){e.preventDefault();e.stopImmediatePropagation();Gravatar.stat('egg');return Gravatar.whee()}return Gravatar.stat('to_gravatar',e)}).bind('contextmenu',function(e){e.preventDefault();e.stopImmediatePropagation();Gravatar.stat('egg');return Gravatar.whee()});jQuery('#profile-'+hash+' a.grav-edit-profile').click(function(e){return Gravatar.stat('click_edit_profile',e)})},"tilt_gravatar":function(){this.active_grav=jQuery('img#'+this.active_id);if(jQuery('img#grav-clone-'+this.active_hash).length){return}this.active_grav_clone=this.active_grav.clone().attr('id','grav-clone-'+this.active_hash).addClass('grav-clone');var top=this.active_grav.offset().top+parseInt(this.active_grav.css('padding-top'),10),left=this.active_grav.offset().left+parseInt(this.active_grav.css('padding-left'),10);var fancyCSS={'-webkit-box-shadow':'0 0 4px rgba(0,0,0,.4)','-moz-box-shadow':'0 0 4px rgba(0,0,0,.4)','box-shadow':'0 0 4px rgba(0,0,0,.4)','border-width':'2px 2px '+(this.active_grav.height()/5)+'px 2px','border-color':'#fff','border-style':'solid','padding':'0px','margin':'-2px 0 0 -2px'};if(jQuery.browser.msie&&9>jQuery.browser.version){fancyCSS['filter']="progid:DXImageTransform.Microsoft.Glow(Color='#aaaaaa', strength='2'";top-=2;left-=2}if(-1==navigator.appVersion.indexOf('Win')){if(jQuery.browser.msie&&9>jQuery.browser.version){fancyCSS['filter']="progid:DXImageTransform.Microsoft.Matrix(M11='1.29683327', M12='0.0906834159', M21='-0.0906834159', M22='1.29683327', SizingMethod='auto expand') "+fancyCSS['filter'];top-=3;left-=4}}else{top-=1;left-=1}if(this.active_grav.hasClass('grav-hijack')){var aWrap='<a href="http://gravatar.com/'+this.active_hash+'" class="grav-clone-a" target="_blank"></a>'}else{var aWrap=this.active_grav.parents('a:first').clone(true).empty()}var appendix=this.active_grav_clone.css(fancyCSS).wrap(aWrap).parent().css({'position':'absolute','top':top+'px','left':left+'px','z-index':15,'border':'none','text-decoration':'none'});jQuery('body').append(appendix);this.active_grav_clone.removeClass('grav-hashed')},"untilt_gravatar":function(){jQuery('img.grav-clone, a.grav-clone-a').remove();Gravatar.hide_throbber()},"show_throbber":function(){if(!Gravatar.throbber){Gravatar.throbber=jQuery('<div id="grav-throbber" style="position: absolute; z-index: 16"><img src="'+this.url_prefix+'.gravatar.com/images/throbber.gif" alt="." width="15" height="15" /></div>')}jQuery('body').append(Gravatar.throbber);var offset=jQuery('#'+Gravatar.active_id).offset();Gravatar.throbber.css({top:offset.top+2+'px',left:offset.left+1+'px'})},"hide_throbber":function(){if(!Gravatar.throbber){return}Gravatar.throbber.remove()},"fetch_profile_by_email":function(email){return this.fetch_profile_by_hash(this.md5(email.toString().toLowerCase()))},"fetch_profile_by_hash":function(hash,dom_id){this.profile_map['g'+hash]=dom_id;if(this.profile_stack['g'+hash]&&'object'==typeof(this.profile_stack['g'+hash])){return this.profile_stack['g'+hash]}this.profile_stack['g'+hash]='fetching';Gravatar.stat('fetch');this.load_js(this.url_prefix+'.gravatar.com/'+hash+'.json?callback=Gravatar.fetch_profile_callback',function(){Gravatar.fetch_profile_error(hash,dom_id)})},"fetch_profile_callback":function(profile){if(!profile||'object'!=typeof(profile)){return}this.profile_stack['g'+profile.entry[0].hash]=profile;this.notify(profile.entry[0].hash)},"fetch_profile_error":function(hash,dom_id){Gravatar.stat('profile_404');Gravatar.profile_map['g'+hash]=false;var grav=jQuery('#'+dom_id);if(grav.parent('a[href="http://gravatar.com/'+hash+'"]').size()){grav.unwrap()}if(dom_id==Gravatar.active_id){Gravatar.hide_card()}},"listen":function(key,callback){if(!this.notify_stack){this.notify_stack={}}key='g'+key;if(!this.notify_stack[key]){this.notify_stack[key]=[]}for(a=0;a<this.notify_stack[key].length;a++){if(callback==this.notify_stack[key][a]){return}}this.notify_stack[key][this.notify_stack[key].length]=callback},"notify":function(key){if(!this.notify_stack){this.notify_stack={}}key='g'+key;if(!this.notify_stack[key]){this.notify_stack[key]=[]}for(a=0;a<this.notify_stack[key].length;a++){if(false==this.notify_stack[key][a]||"undefined"==typeof(this.notify_stack[key][a])){continue}Gravatar[this.notify_stack[key][a]](key.substr(1));this.notify_stack[key][a]=false}},"extract_hash":function(str){hash=/gravatar.com\/avatar\/([0-9a-f]{32})/.exec(jQuery(str).attr('src'));if(null!=hash&&"object"==typeof(hash)&&2==hash.length){hash=hash[1]}else{hash=/gravatar_id\=([0-9a-f]{32})/.exec(jQuery(str).attr('src'));if(null!==hash&&"object"==typeof(hash)&&2==hash.length){hash=hash[1]}else{return false}}return hash},"load_js":function(src,error_handler){if(!this.loaded_scripts){this.loaded_scripts=[]}if(this.loaded_scripts[src]){return}this.loaded_scripts[src]=true;var new_script=document.createElement('script');new_script.src=src;new_script.type='text/javascript';if(jQuery.isFunction(error_handler)){new_script.onerror=error_handler}document.getElementsByTagName('head')[0].appendChild(new_script)},"loaded_js":function(hash,dom_id){Gravatar.profile_cb(hash,dom_id)},"add_card_css":function(){if(jQuery('#gravatar-card-css').length){return}var src=jQuery('script[src*="/js/gprofiles."]').attr('src')||false,url,bust=false;if(src){url=src.replace(/\/js\/gprofiles(?:\.dev)?\.js.*$/,'');bust=src.split('?')[1]||false}else{url='http://s.gravatar.com'}if(!bust){var now=new Date(),janOne=new Date(now.getFullYear(),0,1),bust=Math.ceil((((now-janOne)/86400000)+janOne.getDay()+1)/7),bust='ver='+now.getFullYear().toString()+bust.toString()}new_css="<link rel='stylesheet' type='text/css' id='gravatar-card-css' href='"+url+"/css/hovercard.css?"+bust+"' />";if(!jQuery('#gravatar-card-services-css').length){new_css+="<link rel='stylesheet' type='text/css' id='gravatar-card-services-css' href='"+url+"/css/services.css?"+bust+"' />"}jQuery('head').append(new_css)},"md5":function(str){return hex_md5(str)},"autofill":function(email,map){if(!email.length||-1==email.indexOf('@')){return}this.autofill_map=map;hash=this.md5(email.toString().toLowerCase());if("undefined"==typeof(this.profile_stack['g'+hash])){this.listen(hash,'autofill_data');this.fetch_profile_by_hash(hash)}else{this.autofill_data(hash)}},"autofill_data":function(hash){GProfile.init(this.profile_stack['g'+hash]);for(var m in this.autofill_map){switch(m){case'url':link=GProfile.get('urls');url=('undefined'!=typeof link[0]?link[0]['value']:GProfile.get('profileUrl'));jQuery('#'+this.autofill_map[m]).val(url);break;case'urls':links=GProfile.get('urls');links_str='';for(l=0;l<links.length;l++){links_str+=links[l]['value']+"\n"}jQuery('#'+this.autofill_map[m]).val(links_str);break;default:parts=m.split(/\./);if(parts[1]){val=GProfile.get(m);switch(parts[0]){case'ims':case'phoneNumbers':val=val.value;break;case'emails':val=val[0].value;case'accounts':val=val.url;break}jQuery('#'+this.autofill_map[m]).val(val)}else{jQuery('#'+this.autofill_map[m]).val(GProfile.get(m))}}}},"whee":function(){if(Gravatar.whee.didWhee){return}Gravatar.whee.didWhee=true;if(document.styleSheets[0].addRule){document.styleSheets[0].addRule('.grav-tag a','background-position: 22px 100% !important')}else{jQuery('.grav-tag a').css('background-position','22px 100%')}jQuery('img[src*="gravatar.com/"]').addClass('grav-whee').css({'-webkit-box-shadow':'1px 1px 3px #aaa','-moz-box-shadow':'1px 1px 3px #aaa','box-shadow':'1px 1px 3px #aaa','border':'2px white solid'});var i=0;setInterval(function(){jQuery('.grav-whee').css({'-webkit-transform':'rotate(-'+i+'deg) scale(1.3)','-moz-transform':'rotate(-'+i+'deg) scale(1.3)','transform':'rotate(-'+i+'deg) scale(1.3)'});i++;if(360==i){i=0}},6);return false},"stat":function(stat,e){Gravatar.stats_queue.push(stat);if(e){var diffWindow=e.metaKey||'_blank'==jQuery(e.currentTarget).attr('target');Gravatar.send_stats(function(){if(diffWindow){return}document.location=e.currentTarget.href});return diffWindow}if(Gravatar.stats_queue.length>10){Gravatar.send_stats()}},"send_stats":function(cb){if(!document.images){return}var stats=Gravatar.stats_queue;if(!stats.length){return}var date=new Date();Gravatar.stats_queue=[];url_prefix='http://stats';if('https:'==window.location.protocol)url_prefix='https://ssl-stats';var url=url_prefix+'.wordpress.com/g.gif?v=wpcom2&x_grav-hover='+stats.join(',')+'&rand='+Math.random().toString()+'-'+date.getTime();var img=new Image(1,1);if(jQuery.isFunction(cb)){img.onload=cb}img.src=url}};var GProfile={"data":{},"init":function(data){if('fetching'==data){return false}if('undefined'==typeof(data.entry[0])){return false}GProfile.data=data.entry[0]},"get":function(attr){if(-1!=attr.indexOf('.')){parts=attr.split(/\./);if(GProfile.data[parts[0]]){if(GProfile.data[parts[0]][parts[1]]){return GProfile.data[parts[0]][parts[1]]}for(i=0,s=GProfile.data[parts[0]].length;i<s;i++){if(GProfile.data[parts[0]][i].type&&parts[1]==GProfile.data[parts[0]][i].type||GProfile.data[parts[0]][i].shortname&&parts[1]==GProfile.data[parts[0]][i].shortname||GProfile.data[parts[0]][i].primary&&parts[1]=='primary'){return GProfile.data[parts[0]][i]}}}return''}if(GProfile.data[attr]){return GProfile.data[attr]}if('url'==attr){if(GProfile.data.urls.length){return GProfile.data.urls[0].value}}return''}};var hexcase=0;var b64pad="";var chrsz=8;function hex_md5(s){return binl2hex(core_md5(str2binl(s),s.length*chrsz))}function b64_md5(s){return binl2b64(core_md5(str2binl(s),s.length*chrsz))}function str_md5(s){return binl2str(core_md5(str2binl(s),s.length*chrsz))}function hex_hmac_md5(a,b){return binl2hex(core_hmac_md5(a,b))}function b64_hmac_md5(a,b){return binl2b64(core_hmac_md5(a,b))}function str_hmac_md5(a,b){return binl2str(core_hmac_md5(a,b))}function md5_vm_test(){return hex_md5("abc")=="900150983cd24fb0d6963f7d28e17f72"}function core_md5(x,e){x[e>>5]|=0x80<<((e)%32);x[(((e+64)>>>9)<<4)+14]=e;var a=1732584193;var b=-271733879;var c=-1732584194;var d=271733878;for(var i=0;i<x.length;i+=16){var f=a;var g=b;var h=c;var j=d;a=md5_ff(a,b,c,d,x[i+0],7,-680876936);d=md5_ff(d,a,b,c,x[i+1],12,-389564586);c=md5_ff(c,d,a,b,x[i+2],17,606105819);b=md5_ff(b,c,d,a,x[i+3],22,-1044525330);a=md5_ff(a,b,c,d,x[i+4],7,-176418897);d=md5_ff(d,a,b,c,x[i+5],12,1200080426);c=md5_ff(c,d,a,b,x[i+6],17,-1473231341);b=md5_ff(b,c,d,a,x[i+7],22,-45705983);a=md5_ff(a,b,c,d,x[i+8],7,1770035416);d=md5_ff(d,a,b,c,x[i+9],12,-1958414417);c=md5_ff(c,d,a,b,x[i+10],17,-42063);b=md5_ff(b,c,d,a,x[i+11],22,-1990404162);a=md5_ff(a,b,c,d,x[i+12],7,1804603682);d=md5_ff(d,a,b,c,x[i+13],12,-40341101);c=md5_ff(c,d,a,b,x[i+14],17,-1502002290);b=md5_ff(b,c,d,a,x[i+15],22,1236535329);a=md5_gg(a,b,c,d,x[i+1],5,-165796510);d=md5_gg(d,a,b,c,x[i+6],9,-1069501632);c=md5_gg(c,d,a,b,x[i+11],14,643717713);b=md5_gg(b,c,d,a,x[i+0],20,-373897302);a=md5_gg(a,b,c,d,x[i+5],5,-701558691);d=md5_gg(d,a,b,c,x[i+10],9,38016083);c=md5_gg(c,d,a,b,x[i+15],14,-660478335);b=md5_gg(b,c,d,a,x[i+4],20,-405537848);a=md5_gg(a,b,c,d,x[i+9],5,568446438);d=md5_gg(d,a,b,c,x[i+14],9,-1019803690);c=md5_gg(c,d,a,b,x[i+3],14,-187363961);b=md5_gg(b,c,d,a,x[i+8],20,1163531501);a=md5_gg(a,b,c,d,x[i+13],5,-1444681467);d=md5_gg(d,a,b,c,x[i+2],9,-51403784);c=md5_gg(c,d,a,b,x[i+7],14,1735328473);b=md5_gg(b,c,d,a,x[i+12],20,-1926607734);a=md5_hh(a,b,c,d,x[i+5],4,-378558);d=md5_hh(d,a,b,c,x[i+8],11,-2022574463);c=md5_hh(c,d,a,b,x[i+11],16,1839030562);b=md5_hh(b,c,d,a,x[i+14],23,-35309556);a=md5_hh(a,b,c,d,x[i+1],4,-1530992060);d=md5_hh(d,a,b,c,x[i+4],11,1272893353);c=md5_hh(c,d,a,b,x[i+7],16,-155497632);b=md5_hh(b,c,d,a,x[i+10],23,-1094730640);a=md5_hh(a,b,c,d,x[i+13],4,681279174);d=md5_hh(d,a,b,c,x[i+0],11,-358537222);c=md5_hh(c,d,a,b,x[i+3],16,-722521979);b=md5_hh(b,c,d,a,x[i+6],23,76029189);a=md5_hh(a,b,c,d,x[i+9],4,-640364487);d=md5_hh(d,a,b,c,x[i+12],11,-421815835);c=md5_hh(c,d,a,b,x[i+15],16,530742520);b=md5_hh(b,c,d,a,x[i+2],23,-995338651);a=md5_ii(a,b,c,d,x[i+0],6,-198630844);d=md5_ii(d,a,b,c,x[i+7],10,1126891415);c=md5_ii(c,d,a,b,x[i+14],15,-1416354905);b=md5_ii(b,c,d,a,x[i+5],21,-57434055);a=md5_ii(a,b,c,d,x[i+12],6,1700485571);d=md5_ii(d,a,b,c,x[i+3],10,-1894986606);c=md5_ii(c,d,a,b,x[i+10],15,-1051523);b=md5_ii(b,c,d,a,x[i+1],21,-2054922799);a=md5_ii(a,b,c,d,x[i+8],6,1873313359);d=md5_ii(d,a,b,c,x[i+15],10,-30611744);c=md5_ii(c,d,a,b,x[i+6],15,-1560198380);b=md5_ii(b,c,d,a,x[i+13],21,1309151649);a=md5_ii(a,b,c,d,x[i+4],6,-145523070);d=md5_ii(d,a,b,c,x[i+11],10,-1120210379);c=md5_ii(c,d,a,b,x[i+2],15,718787259);b=md5_ii(b,c,d,a,x[i+9],21,-343485551);a=safe_add(a,f);b=safe_add(b,g);c=safe_add(c,h);d=safe_add(d,j)}return Array(a,b,c,d)}function md5_cmn(q,a,b,x,s,t){return safe_add(bit_rol(safe_add(safe_add(a,q),safe_add(x,t)),s),b)}function md5_ff(a,b,c,d,x,s,t){return md5_cmn((b&c)|((~b)&d),a,b,x,s,t)}function md5_gg(a,b,c,d,x,s,t){return md5_cmn((b&d)|(c&(~d)),a,b,x,s,t)}function md5_hh(a,b,c,d,x,s,t){return md5_cmn(b^c^d,a,b,x,s,t)}function md5_ii(a,b,c,d,x,s,t){return md5_cmn(c^(b|(~d)),a,b,x,s,t)}function core_hmac_md5(a,b){var c=str2binl(a);if(c.length>16)c=core_md5(c,a.length*chrsz);var d=Array(16),opad=Array(16);for(var i=0;i<16;i++){d[i]=c[i]^0x36363636;opad[i]=c[i]^0x5C5C5C5C}var e=core_md5(d.concat(str2binl(b)),512+b.length*chrsz);return core_md5(opad.concat(e),512+128)}function safe_add(x,y){var a=(x&0xFFFF)+(y&0xFFFF);var b=(x>>16)+(y>>16)+(a>>16);return(b<<16)|(a&0xFFFF)}function bit_rol(a,b){return(a<<b)|(a>>>(32-b))}function str2binl(a){var b=Array();var c=(1<<chrsz)-1;for(var i=0;i<a.length*chrsz;i+=chrsz)b[i>>5]|=(a.charCodeAt(i/chrsz)&c)<<(i%32);return b}function binl2str(a){var b="";var c=(1<<chrsz)-1;for(var i=0;i<a.length*32;i+=chrsz)b+=String.fromCharCode((a[i>>5]>>>(i%32))&c);return b}function binl2hex(a){var b=hexcase?"0123456789ABCDEF":"0123456789abcdef";var c="";for(var i=0;i<a.length*4;i++){c+=b.charAt((a[i>>2]>>((i%4)*8+4))&0xF)+b.charAt((a[i>>2]>>((i%4)*8))&0xF)}return c}function binl2b64(a){var b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";var c="";for(var i=0;i<a.length*4;i+=3){var d=(((a[i>>2]>>8*(i%4))&0xFF)<<16)|(((a[i+1>>2]>>8*((i+1)%4))&0xFF)<<8)|((a[i+2>>2]>>8*((i+2)%4))&0xFF);for(var j=0;j<4;j++){if(i*8+j*6>a.length*32)c+=b64pad;else c+=b.charAt((d>>6*(3-j))&0x3F)}}return c};
