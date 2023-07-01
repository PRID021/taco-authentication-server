const input = document.getElementById('username');
input.addEventListener('input', () => {
    input.setAttribute('value', input.value);
});

const pInput = document.getElementById('password');
pInput.addEventListener('input', () => {
    pInput.setAttribute('value', pInput.value);
});

document.addEventListener('DOMContentLoaded', function() {
    var usernameInput = document.getElementById('username');
    var passwordInput = document.getElementById('password');
    
    // Add event listeners to detect changes in the input fields
    usernameInput.addEventListener('input', syncInputValue);
    passwordInput.addEventListener('input', syncInputValue);
  });
  
  function syncInputValue(event) {
    // Update the value of the input field to match the entered content
    this.value = this.value;
  }

const buttons = document.querySelectorAll('a');
buttons.forEach(btn => {
    btn.addEventListener('click', function (e) {

        let x = e.clientX - e.target.offsetLeft;
        let y = e.clientY - e.target.offsetTop;

        let ripples = document.createElement('span');
        ripples.style.left = x + 'px';
        ripples.style.top = y + 'px';
        this.appendChild(ripples);

        setTimeout(() => {
            ripples.remove()
        }, 1000);
    });
});

// for button
function ripple(element, color = '255,255,255', opacity = 0.3, stop = 120) {
    var rgb;
    var els = document.querySelectorAll(element);
    els.forEach(el => {
        el.onclick = function (evt) {
            var x = evt.pageX - el.offsetLeft;
            var y = evt.pageY - el.offsetTop;

            var duration = 600;
            var animationFrame, animationStart;

            var animationStep = timestamp => {
                if (!animationStart) {
                    animationStart = timestamp;
                }

                var frame = timestamp - animationStart;
                if (frame < duration) {
                    var easing = (frame / duration) * (2 - frame / duration);

                    var circle = "circle at " + x + "px " + y + "px";
                    var clr = "rgba(" + color + "," + opacity * (1 - easing) + ")";
                    var stp = stop * easing + "%";
                    el.style.backgroundImage =
                        "radial-gradient(" +
                        circle +
                        ", " +
                        clr +
                        " " +
                        stp +
                        ", transparent " +
                        stp +
                        ")";

                    animationFrame = window.requestAnimationFrame(animationStep);
                } else {
                    el.style.backgroundImage = "none";
                    window.cancelAnimationFrame(animationFrame);
                }
            };

            animationFrame = window.requestAnimationFrame(animationStep);
        };
    });
}
ripple('.btn-green', '0,0,0')
ripple('.btn-purple', '255,255,255')