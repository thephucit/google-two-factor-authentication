<?php namespace Extensions\Thephuc\TFA;

use Backend, Event, View;
use BackendMenu, BackendAuth;
use Backend\Models\User;
use System\Classes\SettingsManager;
use Thephuc\Extensions\Classes\System\ExtensionAbstract;
use Extensions\Thephuc\TFA\Helpers\GoogleAuthenticator;

class Extension extends ExtensionAbstract
{
    protected $slug = 'backend/preferences/tfa-authentication';

    protected $authenticator;

    protected $user;

    const TOLERANCE   = 0;

    const SECRET_SIZE = 120;

    public function __construct()
    {
        $this->authenticator = new GoogleAuthenticator;
    }

    /**
     * @var Boot method, called right before the request route.
     */
    public function boot()
    {
        Event::listen('backend.page.beforeDisplay', function()
        {
            $this->user = BackendAuth::getUser();
            if (request()->slug !== $this->slug) {
                if ($this->isOpenTFA($this->user) && ! $this->user->tfa_is_authenticated) {
                    return redirect(Backend::url($this->slug));
                }
            } else {
                if (! $this->isOpenTFA($this->user) || $this->user->tfa_is_authenticated) {
                    return Backend::redirectIntended('backend');
                }
            }
        });

        /**
         * in first time login if user has openning tfa, but `tfa_is_authenticated` still not reset to false
         * then should be reset it before
         */
        Event::listen('backend.user.login', function($user)
        {
            if ($this->isOpenTFA($user) && $user->tfa_is_authenticated) {
                $user->tfa_is_authenticated = false;
                $user->save();
            }
        });

        $this->addMethods();
    }

    /**
     * Registers any back-end configuration links used by this plugin.
     *
     * @return array
     */
    public function settings()
    {
        return [
            'tfa' => [
                'label'       => 'Two factor authentication',
                'description' => 'Google two factor authentication, add an extra layer of security to your account.',
                'category'    => 'Extensions',
                'icon'        => 'oc-icon-user-secret',
                'url'         => Backend::url('backend/preferences/tfa-settings'),
                'order'       => 1,
                'keywords'    => '',
            ],
        ];
    }

    /**
     * Add dynamic methods to default controller
     */
    private function addMethods()
    {
        \Backend\Controllers\Preferences::extend(function($controller) {
            # Define route go to TFA settings
            if (! $controller->methodExists('tfaSettings')) {
                $controller->addDynamicMethod('tfaSettings', function() use ($controller) {
                    BackendMenu::setContext('October.System', 'system');
                    SettingsManager::setContext('Thephuc.Extensions', 'tfa');

                    $formWidget = $this->createFormWidget($controller);
                    $formWidget->setFormValues(['tfa_is_opened' => $this->user->tfa_is_opened]);
                    return $controller->makePartial('$/extensions/thephuc/tfa/views/settings.htm', [
                        'formWidget' => $formWidget,
                    ]);
                });
            }

            # Define ajax generate QRcode
            if (! $controller->methodExists('onGenerate')) {
                $controller->addDynamicMethod('onGenerate', function() use ($controller) {
                    if ($this->user->tfa_is_opened == post('tfa_is_opened')) {
                        throw new \ValidationException(['nochange' => 'There is no change in your request']);
                    }

                    if (post('tfa_is_opened')) {
                        $secretKey = $this->authenticator->createSecret(self::SECRET_SIZE);
                        $response  = [
                            'isOpened'  => true,
                            'secret'    => $secretKey,
                            'qrCodeUrl' => $this->authenticator->getQRCodeGoogleUrl(
                                str_slug(config('app.name')),
                                $secretKey,
                                config('app.url')
                            ),
                        ];
                    } else {
                        $this->updateSettings();
                    }

                    return response()->json(isset($response) ? $response : ['isOpened' => false]);
                });
            }

            # Show popup result
            if (! $controller->methodExists('onShowPopup')) {
                $controller->addDynamicMethod('onShowPopup', function() use ($controller) {
                    return $controller->makePartial('$/extensions/thephuc/tfa/views/popup.htm', [
                        'image' => post('image'),
                        'secret' => post('secret'),
                    ]);
                });
            }

            # event enable two factor authentication
            if (! $controller->methodExists('onEnable')) {
                $controller->addDynamicMethod('onEnable', function() use ($controller) {
                    $secret = post('secret');
                    $code   = post('code');

                    $checkResult = $this->authenticator->verifyCode($secret, $code, self::TOLERANCE);
                    if (! $checkResult) {
                        throw new \ValidationException([
                            'invalid_code' => 'Unable to validate your token. Please try again'
                        ]);
                    }

                    $this->updateSettings($secret, true, true);
                    \Flash::success('Two factor authentication enabled on your account');
                });
            }

            # show form authenticate
            if (! $controller->methodExists('tfaAuthentication')) {
                $controller->addDynamicMethod('tfaAuthentication', function() use ($controller) {
                    return $controller->makePartial('$/extensions/thephuc/tfa/views/authentication.htm');
                });
            }

            # event cancel authentication, logout and redirect to login page
            if (! $controller->methodExists('onCancelAuthenticate')) {
                $controller->addDynamicMethod('onCancelAuthenticate', function() use ($controller) {
                    BackendAuth::logout();
                    return Backend::redirect('backend');
                });
            }

            # event authentication
            if (! $controller->methodExists('onAuthenticate')) {
                $controller->addDynamicMethod('onAuthenticate', function() use ($controller) {
                    $checkResult = $this->authenticator->verifyCode(
                        $this->user->tfa_secret_key, post('code'), self::TOLERANCE
                    );

                    if (! $checkResult) {
                        throw new \ValidationException(['invalid_code' => 'Unable to validate your token. Please try again']);
                    }
                    $this->user->tfa_is_authenticated = true;
                    $this->user->save();

                    return Backend::redirectIntended('backend');
                });
            }
        });
    }

    /**
     * create form widget
     *
     * @return [object]
     */
    private function createFormWidget($controller)
    {
        $config = $controller->makeConfig('$/extensions/thephuc/tfa/config/form.yaml');
        $config->model = new User;
        $widget = $controller->makeWidget('Backend\Widgets\Form', $config);
        $widget->bindToController();

        return $widget;
    }

    /**
     * update backend user settings
     *
     * @param  string  $secret
     * @param  boolean $opened
     * @param  boolean $authenticated
     */
    private function updateSettings($secret = '', $opened = false, $authenticated = false)
    {
        $this->user->tfa_secret_key = $secret;
        $this->user->tfa_is_opened = $opened;
        $this->user->tfa_is_authenticated = $authenticated;
        $this->user->save();
    }

    /**
     * check user is open two layer authentication
     *
     * @param  object $user
     * @return boolean
     */
    private function isOpenTFA($user)
    {
        return isset($user->tfa_is_opened) && $user->tfa_is_opened;
    }
}
