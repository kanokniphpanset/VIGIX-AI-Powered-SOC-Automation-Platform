<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { settingsApi } from '@/api/vigix'
const user = ref('patsesxan@gmail.com')
const password = ref('')
const configured = ref(false)
const busy = ref(false)
const message = ref('')
onMounted(async () => {
  try { const s = await settingsApi.emailProvider(); user.value = s.user || user.value; configured.value = s.configured }
  catch { message.value = 'อ่านการตั้งค่าอีเมลไม่ได้ กรุณาตรวจสิทธิ์และ backend' }
})
async function save() {
  busy.value = true; message.value = ''
  try {
    const s = await settingsApi.saveEmailProvider(user.value.trim(), password.value || undefined)
    configured.value = s.configured
    message.value = 'บันทึกแล้ว ใช้กับการส่งครั้งถัดไป ยังไม่ได้ตรวจการเชื่อมต่อหรือส่งอีเมล'
  } catch { message.value = 'บันทึกไม่ได้ ตรวจอีเมล Gmail และ App Password 16 ตัวอักษร' }
  finally { password.value = ''; busy.value = false }
}
</script>
<template>
  <form class="mt-4 space-y-3 rounded-lg border border-slate-200 p-4" @submit.prevent="save">
    <h3 class="text-sm font-semibold">ตั้งค่าอีเมลผู้ส่งผ่าน Gmail</h3>
    <p class="text-xs text-slate-500">{{ configured ? 'มีการตั้งค่าแล้ว (ยังไม่ยืนยันการส่ง)' : 'ยังไม่มีการตั้งค่าครบ' }} · บันทึกจากหน้านี้ได้โดยไม่แก้ .env</p>
    <label class="block text-sm">อีเมลผู้ส่ง<input v-model="user" type="email" required autocomplete="off" class="mt-1 block w-full rounded border border-slate-300 p-2" /></label>
    <label class="block text-sm">Gmail App Password<input v-model="password" type="password" autocomplete="new-password" :required="!configured" placeholder="เว้นว่างเพื่อเก็บรหัสเดิม" class="mt-1 block w-full rounded border border-slate-300 p-2" /></label>
    <p class="text-xs text-slate-500">ใช้ App Password ไม่ใช่รหัสล็อกอิน Gmail รหัสถูกเข้ารหัสผูกกับบัญชี Windows ของ backend และไม่ถูกส่งกลับมาแสดง</p>
    <button :disabled="busy" class="rounded-lg bg-slate-900 px-4 py-2 text-sm text-white disabled:opacity-50">{{ busy ? 'กำลังบันทึก…' : 'บันทึกการตั้งค่าอีเมล' }}</button>
    <p v-if="message" role="status" class="text-sm text-slate-700">{{ message }}</p>
  </form>
</template>
