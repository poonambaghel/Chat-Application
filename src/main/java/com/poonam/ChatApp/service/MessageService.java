package com.poonam.ChatApp.service;

import com.poonam.ChatApp.mapper.MessageMapper;
import com.poonam.ChatApp.model.ChatForm;
import com.poonam.ChatApp.model.ChatMessage;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.List;

@Service
public class MessageService {
    MessageMapper messageMapper;

    public MessageService(MessageMapper messageMapper) {
        this.messageMapper = messageMapper;
    }

    @PostConstruct
    public void postConstruct(){
        System.out.println("Creating message service bean");
    }

    public void addMessage(ChatForm chatForm){
        ChatMessage newMessage=new ChatMessage();
        newMessage.setUsername(chatForm.getUsername());
        switch(chatForm.getMessageType()){
            case "Say":
                newMessage.setMessageText(chatForm.getMessageText());
                break;
            case "Shout":
                newMessage.setMessageText(chatForm.getMessageText().toUpperCase());
                break;
            case "Whisper":
                newMessage.setMessageText(chatForm.getMessageText().toLowerCase());
                break;
        }
        messageMapper.addMessage(newMessage);
    }

    public List<ChatMessage> getChatMessages(){
        return messageMapper.getAllMessages();
    }
}
