let isSubmitting = false;
// 配置属性
const CONFIG_ATTR = {
    data: {},
    getBoolean: function (attrName) {
        let config = this.data[attrName];
        if (!config) {
            return false;
        }
        return Boolean(config);
    }
}

function initConfigAttributes() {
    const data = {};
    const templateAttributes = $('#templateAttributes');
    data.passwordNeedEncrypt = templateAttributes.data('password_encrypt')
    data.usernameNeedEncrypt = templateAttributes.data('username_encrypt')
    data.publicKey = templateAttributes.data('public_key')
    CONFIG_ATTR.data = data;
}

(function () {
    'use strict';
    initConfigAttributes();
    window.addEventListener('load', function () {
        /**
         * @type{HTMLFormElement}
         */
        const form = document.getElementById('loginForm');

        form.addEventListener('submit', function (event) {

            event.preventDefault();
            event.stopPropagation();
            console.log(isSubmitting);
            if (isSubmitting) {
                return;
            }
            isSubmitting = true;
            validateForm(form).then(valid => {
                if (valid) {
                    createAndSubmitLogin(new FormData(form))
                }
                isSubmitting = false;
            })
        }, false);
        form.oninput = function (ev) {
            const el = ev.target;
            if (el instanceof HTMLInputElement && el.classList.contains("need-validate")) {
                renderValidStatus(ev.target)
            }
        }
    }, false);
})();


/**
 *
 * @param form{HTMLFormElement}
 * @returns {Promise<boolean>}
 */
async function validateForm(form) {
    const captchaInput = form["captcha"];
    const captchaValid = await verifyCaptcha(captchaInput);
    let validity = form.checkValidity();
    let elements = form.elements;
    for (let i = 0; i < elements.length; i++) {
        let element = elements.item(i);
        if (element.classList.contains("need-validate")) {
            renderValidStatus(element);
        }
    }
    // form.classList.add('was-validated');
    return (validity && captchaValid);
}

/**
 *
 * @param element{HTMLInputElement}
 */
function renderValidStatus(element) {

    if (element.validity.valid) {
        element.classList.remove('is-invalid')
    } else {
        element.classList.add('is-invalid')
        element.classList.remove('is-valid')
    }
}

function encrypt(word) {
    const encrypt = new JSEncrypt();
    encrypt.setPublicKey(CONFIG_ATTR.data['publicKey']);
    return encrypt.encrypt(word);
}


$('img.captcha').click(function () {
    $(this).prop("src", '/login/captcha?t=' + new Date().getTime())
})


function createAndSubmitLogin(formData) {
    let username = formData.get("username");
    let password = formData.get("password");
    let captcha = formData.get("captcha");
    let csrfToken = formData.get("_csrf");
    let submitForm = document.createElement("form");
    submitForm.style.display = "none";
    submitForm.action = "/login";
    submitForm.method = "post";
    submitForm.autocomplete = "off";
    const newUsername = CONFIG_ATTR.getBoolean("usernameNeedEncrypt") ? encrypt(username) : username
    const newPassword = CONFIG_ATTR.getBoolean("passwordNeedEncrypt") ? encrypt(password) : password
    const params = [{
        name: 'username',
        value: newUsername
    }, {
        name: 'password',
        value: newPassword
    }, {
        name: 'captcha',
        value: captcha
    }, {
        name: '_csrf',
        value: csrfToken
    }]

    for (let i = 0; i < params.length; i++) {
        let input = document.createElement("input");
        input.name = params[i].name;
        //防止IE浏览器将null 自动转换为"null" 导致错误
        if (params[i].value !== null) {
            input.value = params[i].value || '';
        }
        submitForm.appendChild(input);
    }


    document.body.appendChild(submitForm);
    submitForm.submit();
}

/**
 *
 * @param captchaInput{HTMLInputElement}
 * @return {Promise<boolean>}
 */
function verifyCaptcha(captchaInput) {
    return new Promise((resolve) => {
        let captcha = captchaInput.value;
        if (!captcha || captcha.length === 0) {
            captchaInput.validity.valueMissing = true;
            captchaInput.nextElementSibling.textContent = '请输入验证码！'
            resolve(false);
            return
        }
        $.ajax({
            url: '/login/verify-captcha',
            type: 'get',
            data: {code: captcha},
            success: function (data) {
                if (!data || !data.failed) {
                    captchaInput.setCustomValidity("");
                    resolve(true);
                } else {
                    captchaInput.setCustomValidity("captcha values do not match.");
                    captchaInput.nextElementSibling.textContent = '验证码错误！'
                    resolve(false);
                }
            },
            error: function (e) {
                resolve(false);
            }
        })
    })
}
