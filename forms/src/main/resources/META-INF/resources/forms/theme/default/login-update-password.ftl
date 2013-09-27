<#import "template-login-action.ftl" as layout>
<@layout.registrationLayout bodyClass=""; section>
    <#if section = "title">

    Update password

    <#elseif section = "header">

    Update password

    <#elseif section = "form">

    <div id="form">
        <form action="${url.passwordUrl}" method="post">
        	<div>
            	<label for="password-new">${rb.getString('passwordNew')}</label>
            	<input type="password" id="password-new" name="password-new" />
        	</div>
        	<div>
        	    <label for="password-confirm">${rb.getString('passwordConfirm')}</label>
    	        <input type="password" id="password-confirm" name="password-confirm" />
	        </div>

            <input class="btn-primary" type="submit" value="Submit" />
        </form>
    </div>

    <#elseif section = "info" >

    <div id="info">
    </div>

    </#if>
</@layout.registrationLayout>