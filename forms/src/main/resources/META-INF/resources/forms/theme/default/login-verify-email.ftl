<#import "template-login-action.ftl" as layout>
<@layout.registrationLayout bodyClass="email"; section>
    <#if section = "title">

    Email verification

    <#elseif section = "header">

    Email verification

    <#elseif section = "feedback">
    <div class="feedback warning show">
        <p><strong>Your account is not enabled because you need to verify your email.</strong><br>Please follow the steps below.</p>
    </div>

    <#elseif section = "form">

    <div class="app-form">
        <p class="instruction">
            Your account is not enabled. An email with instructions to verify your email address has been sent to you.
        </p>
        <p class="instruction">Haven't received a verification code in your email?
            <a href="${url.emailVerificationUrl}">Click here</a> to re-send the email.
        </p>
    </div>

    <#elseif section = "info" >

    </#if>
</@layout.registrationLayout>