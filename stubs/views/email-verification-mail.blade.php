{{--@formatter:off--}}
@component('mail::message')
# Verification Code

Here is your verification code: <br>
<h4 style="text-align: center;
    color: #4C4C4C;
    background-color: ghostwhite;
    letter-spacing: 10px;
    padding-top: 10px;
    padding-bottom: 10px;">{{ $code }}</h4><br>

<i>The code remains valid for 5 minutes.</i><br>

Thanks,<br>
{{ config('app.name') }}
@endcomponent
{{--@formatter:off--}}
