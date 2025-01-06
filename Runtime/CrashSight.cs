using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using System.Runtime.InteropServices;
using System;

// REALLY stop code-stripping removing GB. We mean it!
namespace CrashSightLib.Runtime
{

        public sealed class CrashSight
        {
                [DllImport("__Internal")]
                private static extern void CS_Load();
                [DllImport("__Internal")]
                private static extern void CS_Start(string appid, string reportURL = null);
                [DllImport("__Internal")]
                private static extern void CS_Stop();
                [DllImport("__Internal")]
                private static extern void CS_SetUserId(string userid);
                [DllImport("__Internal")]
                private static extern void CS_SetAppVersion(string version);
                [DllImport("__Internal")]
                private static extern void CS_SetWXAppIdentify(string identify);
                [DllImport("__Internal")]
                private static extern void CS_SetExtKV(string key, string value);
                [DllImport("__Internal")]
                private static extern void CS_ClearExtKV();
                [DllImport("__Internal")]
                private static extern void CS_ReportException(string exceptionName, string message, string stack);
                [DllImport("__Internal")]
                private static extern string CS_JSBacktrace(int skipCount, string excludeFilter, int limitCount);






                private static bool enableAutoFetchJSScriptOnUnCatchedExceptionCalllback = false;
                private static string autoFetchJSScriptOnUnCatchedExceptionExcludeFilter = null;
                private static int autoFetchJSScriptOnUnCatchedExceptionLimitCount = 0;

                private static bool hasLoadSDK = false;

                private static void LoadSDK()
                {
                        if (!hasLoadSDK)
                        {
                                CS_Load();
                        }
                        hasLoadSDK = true;
                }


                private static void _OnUncaughtExceptionHandler(object sender, System.UnhandledExceptionEventArgs args)
                {

                        Debug.Log("[CrashSight] _OnUncaughtExceptionHandler");
                        if (args == null || args.ExceptionObject == null)
                        {
                                return;
                        }

                        try
                        {
                                if (args.ExceptionObject.GetType() == typeof(System.Exception))
                                {
                                        System.Exception exception = (System.Exception)args.ExceptionObject;
                                        CS_ReportException("Unity Uncaught Exception", exception.Message, exception.StackTrace);
                                        return;
                                }
                        }
                        catch
                        {
                        }

                }


                private static void _OnLogCallbackHandler(string condition, string stackTrace, LogType type)
                {
                        if (!string.IsNullOrEmpty(condition) && condition.Contains("[CrashSight"))
                        {
                                return;
                        }

                        if (type == LogType.Exception)
                        {
                                if (stackTrace == null)
                                {
                                        stackTrace = "";
                                }
                                if (enableAutoFetchJSScriptOnUnCatchedExceptionCalllback)
                                {
                                        CS_ReportException("Unity Exception Log", condition, stackTrace + "\njavascript stack:\n" + JSBacktrace(5, autoFetchJSScriptOnUnCatchedExceptionExcludeFilter, autoFetchJSScriptOnUnCatchedExceptionLimitCount));
                                }
                                else
                                {
                                        CS_ReportException("Unity Exception Log", condition, stackTrace);
                                }
                        }

                }


                /// <summary>
                /// 初始化SDK
                /// </summary>
                /// <param name="appid"></param>
                /// <param name="reportURL"></param>
                public static void Start(string appid, string reportURL = null)
                {
                        LoadSDK();
                        CS_Start(appid, reportURL);
                        AppDomain.CurrentDomain.UnhandledException += _OnUncaughtExceptionHandler;
                        Application.logMessageReceived += _OnLogCallbackHandler;


                }

                /// <summary>
                /// 停止SDK
                /// </summary>
                public static void Stop()
                {
                        LoadSDK();
                        AppDomain.CurrentDomain.UnhandledException -= _OnUncaughtExceptionHandler;
                        Application.logMessageReceived -= _OnLogCallbackHandler;
                        CS_Stop();

                }


                public static void EnableAutoFetchJSScriptOnUnCatchedExceptionCalllback(bool enable, string excludeFilter = null, int limitCount = 0)
                {
                        enableAutoFetchJSScriptOnUnCatchedExceptionCalllback = enable;
                        autoFetchJSScriptOnUnCatchedExceptionExcludeFilter = excludeFilter;
                        autoFetchJSScriptOnUnCatchedExceptionLimitCount = limitCount;
                }

                /// <summary>
                /// 设置用户ID
                /// </summary>
                /// <param name="userid"></param>
                public static void SetUserId(string userid)
                {
                        LoadSDK();
                        CS_SetUserId(userid);
                }


                /// <summary>
                /// 设置App版本
                /// </summary>
                /// <param name="version"></param>
                public static void SetAppVersion(string version)
                {
                        LoadSDK();
                        CS_SetAppVersion(version);
                }


                /// <summary>
                /// 设置App唯一标识
                /// </summary>
                /// <param name="identify"></param>
                public static void SetWXAppIdentify(string identify)
                {
                        LoadSDK();
                        CS_SetWXAppIdentify(identify);
                }

                /// <summary>
                /// 设置自定义KV，当value为null时，表示删除当前key
                /// </summary>
                /// <param name="key"></param>
                /// <param name="value"></param>
                public static void SetExtKV(string key, string value)
                {
                        LoadSDK();
                        CS_SetExtKV(key, value);
                }

                /// <summary>
                /// 清空自定义KV
                /// </summary>
                public static void ClearExtKV()
                {
                        LoadSDK();
                        CS_ClearExtKV();
                }


                /// <summary>
                /// 上报自定义异常
                /// </summary>
                /// <param name="exceptionName"></param>
                /// <param name="message"></param>
                /// <param name="stack"></param>
                public static void ReportException(string exceptionName, string message, string stack, string excludeFilter = null, int limitCount = 0, bool appendJSException = true)
                {
                        LoadSDK();
                        if (appendJSException)
                        {
                                CS_ReportException(exceptionName, message, stack + "\njavascript stack:\n" + JSBacktrace(5, excludeFilter, limitCount));
                        }
                        else
                        {
                                CS_ReportException(exceptionName, message, stack);
                        }
                }

                /// <summary>
                /// 获取JS堆栈信息
                /// </summary>
                /// <param name="JSBacktrace"></param>
                public static string JSBacktrace(int skipCount, string excludeFilter = null, int limitCount = 0)
                {
                        return CS_JSBacktrace(skipCount, excludeFilter, limitCount);
                }


        }



}

